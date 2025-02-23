#![allow(non_snake_case)]
#![allow(clippy::missing_transmute_annotations)]
use crate::structs::{
    self, HANDLE, LDR_DATA_TABLE_ENTRY, LIST_ENTRY, PEB, PVOID, RTL_USER_PROCESS_PARAMETERS,
    UNICODE_STRING,
};
use std::arch::asm;
use windows_sys::Win32::{
    Foundation::{FARPROC, HINSTANCE},
    System::{
        Diagnostics::Debug::{IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS64},
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY},
    },
};

#[inline(never)]
#[cfg(target_pointer_width = "64")]
pub unsafe fn __readgsqword(offset: u32) -> u64 {
    let out: u64;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}

#[inline(always)]
pub fn get_module_base_addr(module_name: &str) -> HINSTANCE {
    unsafe {
        let peb_offset: *const u64 = __readgsqword(0x60) as *const u64;
        let rf_peb: *const PEB = peb_offset as *const PEB;
        let peb = *rf_peb;
        let mut p_ldr_data_table_entry: *const LDR_DATA_TABLE_ENTRY =
            (*peb.Ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut p_list_entry = &(*peb.Ldr).InMemoryOrderModuleList as *const LIST_ENTRY;
        loop {
            let buffer = core::slice::from_raw_parts(
                (*p_ldr_data_table_entry).FullDllName.Buffer,
                (*p_ldr_data_table_entry).FullDllName.Length as usize / 2,
            );
            let dll_name = String::from_utf16_lossy(buffer);
            if dll_name.to_lowercase().starts_with(module_name) {
                let module_base: HINSTANCE = (*p_ldr_data_table_entry).Reserved2[0] as HINSTANCE;
                return module_base;
            }
            if p_list_entry == (*peb.Ldr).InMemoryOrderModuleList.Blink {
                // println!("Module not found!");
                return core::ptr::null_mut();
            }
            p_list_entry = (*p_list_entry).Flink;
            p_ldr_data_table_entry = (*p_list_entry).Flink as *const LDR_DATA_TABLE_ENTRY;
        }
    }
}

#[inline(always)]
pub fn get_proc_addr(module_handle: HINSTANCE, function_name: &str) -> FARPROC {
    let mut address_array: u64;
    let mut name_array: u64;
    let mut name_ordinals: u64;
    let nt_headers: *const IMAGE_NT_HEADERS64;
    let data_directory: *const IMAGE_DATA_DIRECTORY;
    let export_directory: *const IMAGE_EXPORT_DIRECTORY;
    let dos_headers: *const IMAGE_DOS_HEADER;
    unsafe {
        dos_headers = module_handle as *const IMAGE_DOS_HEADER;
        nt_headers =
            (module_handle as u64 + (*dos_headers).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
        data_directory =
            (&(*nt_headers).OptionalHeader.DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
        export_directory = (module_handle as u64 + (*data_directory).VirtualAddress as u64)
            as *const IMAGE_EXPORT_DIRECTORY;
        address_array = module_handle as u64 + (*export_directory).AddressOfFunctions as u64;
        name_array = module_handle as u64 + (*export_directory).AddressOfNames as u64;
        name_ordinals = module_handle as u64 + (*export_directory).AddressOfNameOrdinals as u64;
        loop {
            let name_offest: u32 = *(name_array as *const u32);
            let current_function_name =
                std::ffi::CStr::from_ptr((module_handle as u64 + name_offest as u64) as *const i8)
                    .to_str()
                    .unwrap_or_default();
            if current_function_name == function_name {
                address_array +=
                    *(name_ordinals as *const u16) as u64 * (std::mem::size_of::<u32>() as u64);
                let fun_addr: FARPROC = std::mem::transmute(
                    module_handle as u64 + *(address_array as *const u32) as u64,
                );
                return fun_addr;
            }
            name_array += std::mem::size_of::<u32>() as u64;
            name_ordinals += std::mem::size_of::<u16>() as u64;
        }
    }
}

#[macro_export]
macro_rules! dynamic_invoke {
    ($a:expr, $b:expr, $c:expr, $d:expr, $($e:tt)*) => {

        let function_ptr = get_proc_addr($a, $b);
        if function_ptr.is_some()
        {
            $c = std::mem::transmute(function_ptr);
            $d = Some($c($($e)*));
        }
        else {
            $d = None;
        }

    };
}

// Dynamically calls NtAllocateVirtualMemory.
///
/// It returns the NTSTATUS value.
pub fn nt_allocate_virtual_memory(
    handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: usize,
    size: *mut usize,
    allocation_type: u32,
    protection: u32,
) -> i32 {
    unsafe {
        let ret;
        let func_ptr: structs::NtAllocateVirtualMemory;
        let ntdll = get_module_base_addr("ntdll.dll");

        dynamic_invoke!(
            ntdll,
            "NtAllocateVirtualMemory",
            func_ptr,
            ret,
            handle,
            base_address,
            zero_bits,
            size,
            allocation_type,
            protection
        );
        ret.unwrap_or(-1)
    }
}

/// Dynamically calls NtWriteVirtualMemory.
///
/// It returns the NTSTATUS value.
pub fn nt_write_virtual_memory(
    handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    size: usize,
    bytes_written: *mut usize,
) -> i32 {
    unsafe {
        let ret;
        let func_ptr: structs::NtWriteVirtualMemory;
        let ntdll = get_module_base_addr("ntdll.dll");

        dynamic_invoke!(
            ntdll,
            "NtWriteVirtualMemory",
            func_ptr,
            ret,
            handle,
            base_address,
            buffer,
            size,
            bytes_written
        );
        ret.unwrap_or(-1)
    }
}

pub fn nt_resume_thread(handle: HANDLE, suspend_count: *mut u32) -> i32 {
    unsafe {
        let ret;
        let func_ptr: structs::NtResumeThread;
        let ntdll = get_module_base_addr("ntdll.dll");

        dynamic_invoke!(
            ntdll,
            "NtResumeThread",
            func_ptr,
            ret,
            handle,
            suspend_count
        );
        ret.unwrap_or(-1)
    }
}

/// Dynamically calls NtProtectVirtualMemory.
///
/// It returns the NTSTATUS value.
pub fn nt_protect_virtual_memory(
    handle: HANDLE,
    base_address: *mut PVOID,
    size: *mut usize,
    new_protection: u32,
    old_protection: *mut u32,
) -> i32 {
    unsafe {
        let ret;
        let func_ptr: structs::NtProtectVirtualMemory;
        let ntdll = get_module_base_addr("ntdll.dll");

        dynamic_invoke!(
            ntdll,
            "NtProtectVirtualMemory",
            func_ptr,
            ret,
            handle,
            base_address,
            size,
            new_protection,
            old_protection
        );
        ret.unwrap_or(-1)
    }
}

/// Dynamically calls NtCreateUserProcess.
///
/// It returns the NTSTATUS value.
#[allow(clippy::too_many_arguments)]
pub fn nt_create_user_process(
    ProcessHandle: *mut HANDLE,
    ThreadHandle: *mut HANDLE,
    ProcessDesiredAccess: u32,
    ThreadDesiredAccess: u32,
    ProcessObjectAttributes: PVOID,
    ThreadObjectAttributes: PVOID,
    ProcessFlags: u32,
    ThreadFlags: u32,
    ProcessParameters: PVOID,
    CreateInfo: PVOID,
    AttributeList: structs::PsAttributeList,
) -> i32 {
    unsafe {
        let ret;
        let func_ptr: structs::NtCreateUserProcess;
        let ntdll = get_module_base_addr("ntdll.dll");
        dynamic_invoke!(
            ntdll,
            "NtCreateUserProcess",
            func_ptr,
            ret,
            ProcessHandle,
            ThreadHandle,
            ProcessDesiredAccess,
            ThreadDesiredAccess,
            ProcessObjectAttributes,
            ThreadObjectAttributes,
            ProcessFlags,
            ThreadFlags,
            ProcessParameters,
            CreateInfo,
            AttributeList
        );

        ret.unwrap_or(-1)
    }
}

/// Dynamically calls RtlInitUnicodeString.
///
/// It returns the NTSTATUS value.
pub fn rtl_init_unicode_string(
    unicode_string: *mut structs::UNICODE_STRING,
    source_string: *const u16,
) {
    unsafe {
        let _ret;
        let func_ptr: structs::RtlInitUnicodeString;
        let ntdll = get_module_base_addr("ntdll.dll");
        dynamic_invoke!(
            ntdll,
            "RtlInitUnicodeString",
            func_ptr,
            _ret,
            unicode_string,
            source_string
        );
    }
}

/// Dynamically calls RtlCreateProcessParametersEx
///
/// It returns the NTSTATUS value.
#[allow(clippy::too_many_arguments)]
pub fn rtl_create_process_parameters_ex(
    pProcessParameters: *mut *mut RTL_USER_PROCESS_PARAMETERS,
    ImagePathName: *mut UNICODE_STRING,
    DllPath: *mut UNICODE_STRING,
    CurrentDirectory: *mut UNICODE_STRING,
    CommandLine: *mut UNICODE_STRING,
    Environment: PVOID,
    WindowTitle: *mut UNICODE_STRING,
    DesktopInfo: *mut UNICODE_STRING,
    ShellInfo: *mut UNICODE_STRING,
    RuntimeData: *mut UNICODE_STRING,
    Flags: u32,
) -> i32 {
    unsafe {
        let ret;
        let func_ptr: structs::RtlCreateProcessParametersEx;
        let ntdll = get_module_base_addr("ntdll.dll");
        dynamic_invoke!(
            ntdll,
            "RtlCreateProcessParametersEx",
            func_ptr,
            ret,
            pProcessParameters,
            ImagePathName,
            DllPath,
            CurrentDirectory,
            CommandLine,
            Environment,
            WindowTitle,
            DesktopInfo,
            ShellInfo,
            RuntimeData,
            Flags
        );
        ret.unwrap_or(-1)
    }
}
