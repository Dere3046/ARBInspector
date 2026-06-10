pub mod header;
pub mod parser;

pub mod defines {
    pub const MBN_HDR_SIZE: usize = 40;
    pub const MBN_V7_HDR_SIZE: usize = 64;
    pub const MBN_V8_HDR_SIZE: usize = 80;

    pub const MBN_V3: u32 = 3;
    pub const MBN_V5: u32 = 5;
    pub const MBN_V6: u32 = 6;
    pub const MBN_V7: u32 = 7;
    pub const MBN_V8: u32 = 8;

    pub const IMAGE_ID_OFFSET: usize = 0;
    pub const VERSION_OFFSET: usize = 4;
    pub const IMAGE_SRC_OFFSET: usize = 8;
    pub const IMAGE_DEST_PTR_OFFSET: usize = 12;
    pub const IMAGE_SIZE_OFFSET: usize = 16;
    pub const CODE_SIZE_OFFSET: usize = 20;
    pub const SIG_PTR_OFFSET: usize = 24;
    pub const SIG_SIZE_OFFSET: usize = 28;
    pub const CERT_CHAIN_PTR_OFFSET: usize = 32;
    pub const CERT_CHAIN_SIZE_OFFSET: usize = 36;

    pub const MBN_V7_SIG2_PTR_OFFSET: usize = 40;
    pub const MBN_V7_SIG2_SIZE_OFFSET: usize = 44;
    pub const MBN_V7_CERT2_PTR_OFFSET: usize = 48;
    pub const MBN_V7_CERT2_SIZE_OFFSET: usize = 52;
    pub const MBN_V7_RESERVED_OFFSET: usize = 56;

    pub const MBN_V8_OEM_SIG_PTR_OFFSET: usize = 40;
    pub const MBN_V8_OEM_SIG_SIZE_OFFSET: usize = 44;
    pub const MBN_V8_OEM_CERT_PTR_OFFSET: usize = 48;
    pub const MBN_V8_OEM_CERT_SIZE_OFFSET: usize = 52;
    pub const MBN_V8_OEM_SIG2_PTR_OFFSET: usize = 56;
    pub const MBN_V8_OEM_SIG2_SIZE_OFFSET: usize = 60;
    pub const MBN_V8_OEM_CERT2_PTR_OFFSET: usize = 64;
    pub const MBN_V8_OEM_CERT2_SIZE_OFFSET: usize = 68;
    pub const MBN_V8_RESERVED_OFFSET: usize = 72;

    pub fn is_valid_version(version: u32) -> bool {
        matches!(version, MBN_V3 | MBN_V5 | MBN_V6 | MBN_V7 | MBN_V8)
    }

    pub fn header_size_for_version(version: u32) -> usize {
        match version {
            MBN_V7 => MBN_V7_HDR_SIZE,
            MBN_V8 => MBN_V8_HDR_SIZE,
            _ => MBN_HDR_SIZE,
        }
    }
}
