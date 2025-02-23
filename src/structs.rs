#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::upper_case_acronyms)]

use core::ffi::c_void;
pub type PVOID = *mut c_void;
pub type NtAllocateVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, usize, *mut usize, u32, u32) -> i32;
pub type NtWriteVirtualMemory =
    unsafe extern "system" fn(HANDLE, PVOID, PVOID, usize, *mut usize) -> i32;
pub type NtProtectVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut PVOID, *mut usize, u32, *mut u32) -> i32;
pub type NtResumeThread = unsafe extern "system" fn(HANDLE, *mut u32) -> i32;
pub type NtCreateUserProcess = unsafe extern "system" fn(
    *mut HANDLE,
    *mut HANDLE,
    u32,
    u32,
    *mut c_void,
    *mut c_void,
    u32,
    u32,
    *mut c_void,
    *mut c_void,
    PsAttributeList,
) -> i32;
pub type RtlInitUnicodeString = unsafe extern "system" fn(*mut UNICODE_STRING, *const u16);
pub type RtlCreateProcessParametersEx = unsafe extern "system" fn(
    *mut *mut RTL_USER_PROCESS_PARAMETERS,
    *mut UNICODE_STRING,
    *mut UNICODE_STRING,
    *mut UNICODE_STRING,
    *mut UNICODE_STRING,
    PVOID,
    *mut UNICODE_STRING,
    *mut UNICODE_STRING,
    *mut UNICODE_STRING,
    *mut UNICODE_STRING,
    u32,
) -> i32;

pub const PAGE_READWRITE: u32 = 0x4;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const PROCESS_ALL_ACCESS: u32 = 2097151;
pub const THREAD_ALL_ACCESS: u32 = 2097151;

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct HANDLE {
    pub id: isize,
}

pub type ULONG = u32;

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub Reserved2: [*mut core::ffi::c_void; 2],
    pub DllBase: PVOID,
    pub EntryPoint: PVOID,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: u32,
    pub LoadCount: u16,
    pub TlsIndex: u16,
    pub HashLinks: LIST_ENTRY,
    pub TimeDateStamp: u32,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u8,
    pub SsHandle: PVOID,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub BitField: u8,
    pub Mutant: PVOID,
    pub ImageBaseAddress: PVOID,
    pub Ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

pub type ULONG_PTR = usize;
pub type SIZE_T = ULONG_PTR;

#[repr(C)]
pub struct PsAttributeList {
    pub total_length: SIZE_T,
    pub attributes: [ntapi::ntpsapi::PS_ATTRIBUTE; 2],
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub Reserved1: [u8; 16],
    pub Reserved2: [*mut c_void; 10],
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
}
