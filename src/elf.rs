pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const EI_CLASS: usize = 4;
pub const EI_DATA: usize = 5;
pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;

pub const PF_PERM_MASK: u32 = 0x7;
pub const PF_OS_SEGMENT_TYPE_MASK: u32 = 0x0700_0000;
pub const PF_OS_ACCESS_TYPE_MASK: u32 = 0x00E0_0000;
pub const PF_OS_PAGE_MODE_MASK: u32 = 0x0010_0000;

pub const PF_OS_SEGMENT_HASH: u32 = 0x2;
pub const PF_OS_SEGMENT_PHDR: u32 = 0x7;

pub const PF_OS_ACCESS_RW: u32 = 0x0;
pub const PF_OS_ACCESS_RO: u32 = 0x1;
pub const PF_OS_ACCESS_ZI: u32 = 0x2;
pub const PF_OS_ACCESS_NOTUSED: u32 = 0x3;
pub const PF_OS_ACCESS_SHARED: u32 = 0x4;

pub const PF_OS_NON_PAGED_SEGMENT: u32 = 0x0;
pub const PF_OS_PAGED_SEGMENT: u32 = 0x1;

pub const ELF_BLOCK_ALIGN: u64 = 0x1000;

pub const ELF32_HDR_SIZE: usize = 52;
pub const ELF64_HDR_SIZE: usize = 64;
pub const ELF32_PHDR_SIZE: usize = 32;
pub const ELF64_PHDR_SIZE: usize = 56;

pub fn perm_to_string(perm: u32) -> &'static str {
    match perm {
        0x1 => "E",
        0x2 => "W",
        0x3 => "WE",
        0x4 => "R",
        0x5 => "RE",
        0x6 => "RW",
        0x7 => "RWE",
        _ => "None",
    }
}

#[inline]
pub fn get_perm_value(flags: u32) -> u32 {
    flags & PF_PERM_MASK
}

#[inline]
pub fn get_os_segment_type(flags: u32) -> u32 {
    (flags & PF_OS_SEGMENT_TYPE_MASK) >> 24
}

#[inline]
pub fn get_os_access_type(flags: u32) -> u32 {
    (flags & PF_OS_ACCESS_TYPE_MASK) >> 21
}

#[inline]
pub fn get_os_page_mode(flags: u32) -> u32 {
    (flags & PF_OS_PAGE_MODE_MASK) >> 20
}

pub fn os_segment_type_to_string(seg_type: u32) -> &'static str {
    match seg_type {
        PF_OS_SEGMENT_HASH => "HASH",
        PF_OS_SEGMENT_PHDR => "PHDR",
        0x0 => "L4",
        0x1 => "AMSS",
        0x3 => "BOOT",
        0x4 => "L4BSP",
        0x5 => "SWAPPED",
        0x6 => "SWAP_POOL",
        _ => "Unknown",
    }
}

pub fn os_access_type_to_string(access_type: u32) -> &'static str {
    match access_type {
        PF_OS_ACCESS_RW => "RW",
        PF_OS_ACCESS_RO => "RO",
        PF_OS_ACCESS_ZI => "ZI",
        PF_OS_ACCESS_NOTUSED => "NOTUSED",
        PF_OS_ACCESS_SHARED => "SHARED",
        _ => "Unknown",
    }
}

pub fn os_page_mode_to_string(page_mode: u32) -> &'static str {
    match page_mode {
        PF_OS_NON_PAGED_SEGMENT => "NON_PAGED",
        PF_OS_PAGED_SEGMENT => "PAGED",
        _ => "Unknown",
    }
}

pub fn p_type_to_string(p_type: u32) -> &'static str {
    match p_type {
        PT_NULL => "NULL",
        PT_LOAD => "LOAD",
        PT_NOTE => "NOTE",
        PT_PHDR => "PHDR",
        _ => "OTHER",
    }
}