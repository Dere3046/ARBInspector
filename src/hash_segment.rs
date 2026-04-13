#![allow(dead_code)]

pub const HASH_SEGMENT_V3: u32 = 3;
pub const HASH_SEGMENT_V5: u32 = 5;
pub const HASH_SEGMENT_V6: u32 = 6;
pub const HASH_SEGMENT_V7: u32 = 7;
pub const HASH_SEGMENT_V8: u32 = 8;

pub const HASH_TABLE_HEADER_SIZE: usize = 40;
pub const HASH_TABLE_HEADER_SIZE_V7: usize = 56;

pub const METADATA_MAJOR_VERSION_0: u32 = 0;
pub const METADATA_MAJOR_VERSION_1: u32 = 1;
pub const METADATA_MINOR_VERSION_0: u32 = 0;

pub const METADATA_MAJOR_VERSION_2: u32 = 2;
pub const METADATA_MAJOR_VERSION_3: u32 = 3;
pub const METADATA_MINOR_VERSION_1: u32 = 1;

pub const COMMON_METADATA_MAJOR_VERSION_0: u32 = 0;
pub const COMMON_METADATA_MINOR_VERSION_0: u32 = 0;
pub const COMMON_METADATA_MINOR_VERSION_1: u32 = 1;

pub const VERSION_MIN: u32 = 1;
pub const VERSION_MAX: u32 = 1000;
pub const COMMON_SIZE_MAX: usize = 0x1000;
pub const QTI_SIZE_MAX: usize = 0x1000;
pub const OEM_SIZE_MAX: usize = 0x4000;
pub const HASH_TABLE_SIZE_MAX: usize = 0x10000;
pub const ARB_VALUE_MAX: u32 = 127;

pub const SHA256_SIZE: usize = 32;
pub const SHA384_SIZE: usize = 48;
pub const SHA512_SIZE: usize = 64;

pub const PAD_BYTE_0: u8 = 0x00;
pub const PAD_BYTE_1: u8 = 0xFF;

pub const AUTHORITY_QTI: &str = "qti";
pub const AUTHORITY_OEM: &str = "oem";

pub fn get_hash_table_header_size(version: u32) -> usize {
    match version {
        HASH_SEGMENT_V3 | HASH_SEGMENT_V5 | HASH_SEGMENT_V6 => HASH_TABLE_HEADER_SIZE,
        HASH_SEGMENT_V7 | HASH_SEGMENT_V8 => HASH_TABLE_HEADER_SIZE_V7,
        _ => HASH_TABLE_HEADER_SIZE,
    }
}

pub fn is_valid_hash_segment_version(version: u32) -> bool {
    matches!(version, HASH_SEGMENT_V3 | HASH_SEGMENT_V5 | HASH_SEGMENT_V6 | HASH_SEGMENT_V7 | HASH_SEGMENT_V8)
}