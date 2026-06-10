pub mod encryption;
pub mod header;
pub mod metadata;
pub mod parser;
pub mod writer;

pub mod defines {
    pub const HASH_SEGMENT_V3: u32 = 3;
    pub const HASH_SEGMENT_V5: u32 = 5;
    pub const HASH_SEGMENT_V6: u32 = 6;
    pub const HASH_SEGMENT_V7: u32 = 7;
    pub const HASH_SEGMENT_V8: u32 = 8;

    pub const HASH_TABLE_HEADER_SIZE: usize = 40;
    pub const HASH_TABLE_HEADER_SIZE_V7: usize = 40;
    pub const HASH_TABLE_HEADER_SIZE_V8: usize = 56;

    pub const NUM_SOC_HW_VERS: usize = 12;
    pub const NUM_SERIAL_NUMBERS: usize = 8;

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

    pub const HASH_ALGO_NA: u32 = 0;
    pub const HASH_ALGO_SHA256: u32 = 2;
    pub const HASH_ALGO_SHA384: u32 = 3;
    pub const HASH_ALGO_SHA512: u32 = 5;

    pub fn hash_algo_size(algo: u32) -> usize {
        match algo {
            HASH_ALGO_SHA256 => SHA256_SIZE,
            HASH_ALGO_SHA384 => SHA384_SIZE,
            HASH_ALGO_SHA512 => SHA512_SIZE,
            _ => SHA256_SIZE,
        }
    }

    pub const PAD_BYTE_0: u8 = 0x00;
    pub const PAD_BYTE_1: u8 = 0xFF;

    pub const AUTHORITY_QTI: &str = "QTI";
    pub const AUTHORITY_OEM: &str = "OEM";

    pub const METADATA_MAJOR_VERSION_0: u32 = 0;
    pub const METADATA_MAJOR_VERSION_1: u32 = 1;
    pub const METADATA_MINOR_VERSION_0: u32 = 0;

    pub const METADATA_MAJOR_VERSION_2: u32 = 2;
    pub const METADATA_MAJOR_VERSION_3: u32 = 3;
    pub const METADATA_MINOR_VERSION_1: u32 = 1;

    pub const COMMON_METADATA_MAJOR_VERSION_0: u32 = 0;
    pub const COMMON_METADATA_MINOR_VERSION_0: u32 = 0;
    pub const COMMON_METADATA_MINOR_VERSION_1: u32 = 1;

    pub fn is_valid_hash_segment_version(version: u32) -> bool {
        matches!(
            version,
            HASH_SEGMENT_V3 | HASH_SEGMENT_V5 | HASH_SEGMENT_V6 | HASH_SEGMENT_V7 | HASH_SEGMENT_V8
        )
    }

    pub fn hash_table_header_size(version: u32) -> usize {
        match version {
            HASH_SEGMENT_V8 => HASH_TABLE_HEADER_SIZE_V8,
            HASH_SEGMENT_V3 | HASH_SEGMENT_V5 | HASH_SEGMENT_V6 | HASH_SEGMENT_V7 => HASH_TABLE_HEADER_SIZE_V7,
            _ => HASH_TABLE_HEADER_SIZE,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_hash_table_header_sizes() {
            assert_eq!(hash_table_header_size(HASH_SEGMENT_V3), 40);
            assert_eq!(hash_table_header_size(HASH_SEGMENT_V5), 40);
            assert_eq!(hash_table_header_size(HASH_SEGMENT_V6), 40);
            assert_eq!(hash_table_header_size(HASH_SEGMENT_V7), 40);
            assert_eq!(hash_table_header_size(HASH_SEGMENT_V8), 56);
            assert_eq!(hash_table_header_size(0), 40);
            assert_eq!(hash_table_header_size(99), 40);
        }

        #[test]
        fn test_is_valid_version() {
            assert!(is_valid_hash_segment_version(3));
            assert!(is_valid_hash_segment_version(5));
            assert!(is_valid_hash_segment_version(6));
            assert!(is_valid_hash_segment_version(7));
            assert!(is_valid_hash_segment_version(8));
            assert!(!is_valid_hash_segment_version(0));
            assert!(!is_valid_hash_segment_version(4));
            assert!(!is_valid_hash_segment_version(9));
        }

        #[test]
        fn test_hash_algo_sizes() {
            assert_eq!(hash_algo_size(HASH_ALGO_SHA256), 32);
            assert_eq!(hash_algo_size(HASH_ALGO_SHA384), 48);
            assert_eq!(hash_algo_size(HASH_ALGO_SHA512), 64);
            assert_eq!(hash_algo_size(0), 32);
            assert_eq!(hash_algo_size(99), 32);
        }

        #[test]
        fn test_constants() {
            assert_eq!(ARB_VALUE_MAX, 127);
            assert_eq!(SHA256_SIZE, 32);
            assert_eq!(SHA384_SIZE, 48);
            assert_eq!(SHA512_SIZE, 64);
            assert_eq!(COMMON_SIZE_MAX, 0x1000);
            assert_eq!(OEM_SIZE_MAX, 0x4000);
            assert_eq!(NUM_SOC_HW_VERS, 12);
            assert_eq!(NUM_SERIAL_NUMBERS, 8);
        }
    }
}
