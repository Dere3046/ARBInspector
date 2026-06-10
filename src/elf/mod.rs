pub mod header;
pub mod program_header;
pub mod parser;

pub mod defines {
    pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
    pub const EI_CLASS: usize = 4;
    pub const EI_DATA: usize = 5;
    pub const E_IDENT_SIZE: usize = 16;

    pub const ELFCLASSNONE: u8 = 0;
    pub const ELFCLASS32: u8 = 1;
    pub const ELFCLASS64: u8 = 2;

    pub const ELFDATANONE: u8 = 0;
    pub const ELFDATA2LSB: u8 = 1;
    pub const ELFDATA2MSB: u8 = 2;

    pub const EV_NONE: u32 = 0;
    pub const EV_CURRENT: u32 = 1;

    pub const ELF32_HDR_SIZE: usize = 52;
    pub const ELF64_HDR_SIZE: usize = 64;
    pub const ELF32_PHDR_SIZE: usize = 32;
    pub const ELF64_PHDR_SIZE: usize = 56;

    pub const PT_NULL: u32 = 0;
    pub const PT_LOAD: u32 = 1;
    pub const PT_DYNAMIC: u32 = 2;
    pub const PT_INTERP: u32 = 3;
    pub const PT_NOTE: u32 = 4;
    pub const PT_SHLIB: u32 = 5;
    pub const PT_PHDR: u32 = 6;
    pub const PT_ONE_SHOT_HASH: u32 = 1879048192;

    pub const P_FLAGS_OS_SEGMENT_TYPE_MASK: u32 = 0x0700_0000;
    pub const P_FLAGS_OS_SEGMENT_TYPE_SHIFT: u32 = 24;

    pub const P_FLAGS_OS_PAGE_MODE_MASK: u32 = 0x0010_0000;
    pub const P_FLAGS_OS_PAGE_MODE_SHIFT: u32 = 20;

    pub const P_FLAGS_OS_ACCESS_TYPE_MASK: u32 = 0x00E0_0000;
    pub const P_FLAGS_OS_ACCESS_TYPE_SHIFT: u32 = 21;

    pub const PF_PERM_MASK: u32 = 0x7;

    pub const P_FLAGS_OS_SEGMENT_L4: u32 = 0;
    pub const P_FLAGS_OS_SEGMENT_AMSS: u32 = 1;
    pub const P_FLAGS_OS_SEGMENT_HASH: u32 = 2;
    pub const P_FLAGS_OS_SEGMENT_BOOT: u32 = 3;
    pub const P_FLAGS_OS_SEGMENT_L4BSP: u32 = 4;
    pub const P_FLAGS_OS_SEGMENT_SWAPPED: u32 = 5;
    pub const P_FLAGS_OS_SEGMENT_SWAP_POOL: u32 = 6;
    pub const P_FLAGS_OS_SEGMENT_PHDR: u32 = 7;

    pub const PF_OS_NON_PAGED_SEGMENT: u32 = 0;
    pub const PF_OS_PAGED_SEGMENT: u32 = 1;

    pub const PF_OS_ACCESS_RW: u32 = 0;
    pub const PF_OS_ACCESS_RO: u32 = 1;
    pub const PF_OS_ACCESS_ZI: u32 = 2;
    pub const PF_OS_ACCESS_NOTUSED: u32 = 3;
    pub const PF_OS_ACCESS_SHARED: u32 = 4;

    pub const ELF_BLOCK_SIZE: u64 = 4096;
    pub const ELF_BLOCK_ALIGN: u64 = 0x1000;

    pub fn p_flags_os_segment_type(flags: u32) -> u32 {
        (flags & P_FLAGS_OS_SEGMENT_TYPE_MASK) >> P_FLAGS_OS_SEGMENT_TYPE_SHIFT
    }

    pub fn p_flags_os_page_mode(flags: u32) -> u32 {
        (flags & P_FLAGS_OS_PAGE_MODE_MASK) >> P_FLAGS_OS_PAGE_MODE_SHIFT
    }

    pub fn p_flags_os_access_type(flags: u32) -> u32 {
        (flags & P_FLAGS_OS_ACCESS_TYPE_MASK) >> P_FLAGS_OS_ACCESS_TYPE_SHIFT
    }

    pub fn get_perm_value(flags: u32) -> u32 {
        flags & PF_PERM_MASK
    }

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

    pub fn p_type_to_string(p_type: u32) -> &'static str {
        match p_type {
            PT_NULL => "NULL",
            PT_LOAD => "LOAD",
            PT_DYNAMIC => "DYNAMIC",
            PT_INTERP => "INTERP",
            PT_NOTE => "NOTE",
            PT_SHLIB => "SHLIB",
            PT_PHDR => "PHDR",
            PT_ONE_SHOT_HASH => "ONE_SHOT_HASH",
            _ => "OTHER",
        }
    }

    pub fn os_segment_type_to_string(seg_type: u32) -> &'static str {
        match seg_type {
            P_FLAGS_OS_SEGMENT_HASH => "HASH",
            P_FLAGS_OS_SEGMENT_PHDR => "PHDR",
            P_FLAGS_OS_SEGMENT_L4 => "L4",
            P_FLAGS_OS_SEGMENT_AMSS => "AMSS",
            P_FLAGS_OS_SEGMENT_BOOT => "BOOT",
            P_FLAGS_OS_SEGMENT_L4BSP => "L4BSP",
            P_FLAGS_OS_SEGMENT_SWAPPED => "SWAPPED",
            P_FLAGS_OS_SEGMENT_SWAP_POOL => "SWAP_POOL",
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
}
