#![allow(dead_code)]

use crate::data::{read_le_u32, read_le_u64};
use crate::hash_segment::defines::{NUM_SOC_HW_VERS, NUM_SERIAL_NUMBERS};

// Common metadata v7 24B: major,minor,software_id,secondary_sw_id,hash_algo,mrc_target

#[derive(Debug, Clone)]
pub struct CommonMetadataV00 {
    pub major_version: u32,
    pub minor_version: u32,
    pub software_id: u32,
    pub secondary_software_id: u32,
    pub hash_table_algorithm: u32,
    pub measurement_register_target: u32,
}

impl CommonMetadataV00 {
    pub const SIZE: usize = 24;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::SIZE {
            return Err("Insufficient data for CommonMetadataV00");
        }
        Ok(CommonMetadataV00 {
            major_version: read_le_u32(data, 0),
            minor_version: read_le_u32(data, 4),
            software_id: read_le_u32(data, 8),
            secondary_software_id: read_le_u32(data, 12),
            hash_table_algorithm: read_le_u32(data, 16),
            measurement_register_target: read_le_u32(data, 20),
        })
    }
}

#[derive(Debug, Clone)]
pub struct CommonMetadataV01 {
    pub base: CommonMetadataV00,
    pub zi_segment_hash_algorithm: u32,
}

impl CommonMetadataV01 {
    pub const SIZE: usize = 28;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = CommonMetadataV00::from_bytes(data)?;
        if data.len() < Self::SIZE {
            return Err("Insufficient data for CommonMetadataV01");
        }
        Ok(CommonMetadataV01 {
            base,
            zi_segment_hash_algorithm: read_le_u32(data, 24),
        })
    }
}

// Metadata v6 V00 120B layout

#[derive(Debug, Clone)]
pub struct MetadataV00 {
    pub major_version: u32,
    pub minor_version: u32,
    pub software_id: u32,
    pub jtag_id: u32,
    pub oem_id: u32,
    pub oem_product_id: u32,
    pub secondary_software_id: u32,
    pub flags: u32,
    pub soc_hw_vers: Vec<u32>,
    pub serial_numbers: Vec<u32>,
    pub mrc_index: u32,
    pub anti_rollback_version: u32,
}

impl MetadataV00 {
    pub const SIZE: usize = 120;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::SIZE {
            return Err("Insufficient data for MetadataV00");
        }
        let mut soc_hw_vers = Vec::with_capacity(NUM_SOC_HW_VERS);
        for i in 0..NUM_SOC_HW_VERS {
            soc_hw_vers.push(read_le_u32(data, 24 + i * 4));
        }
        let mut serial_numbers = Vec::with_capacity(NUM_SERIAL_NUMBERS);
        for i in 0..NUM_SERIAL_NUMBERS {
            serial_numbers.push(read_le_u32(data, 72 + i * 4));
        }
        Ok(MetadataV00 {
            major_version: read_le_u32(data, 0),
            minor_version: read_le_u32(data, 4),
            software_id: read_le_u32(data, 8),
            jtag_id: read_le_u32(data, 12),
            oem_id: read_le_u32(data, 16),
            oem_product_id: read_le_u32(data, 20),
            secondary_software_id: read_le_u32(data, 104),
            flags: read_le_u32(data, 108),
            soc_hw_vers,
            serial_numbers,
            mrc_index: read_le_u32(data, 112),
            anti_rollback_version: read_le_u32(data, 116),
        })
    }

    pub fn get_arb_version(&self) -> u32 {
        self.anti_rollback_version
    }
}

// Metadata v6 V10 extends V00

#[derive(Debug, Clone)]
pub struct MetadataV10 {
    pub base: MetadataV00,
}

impl MetadataV10 {
    pub const SIZE: usize = 120;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = MetadataV00::from_bytes(data)?;
        Ok(MetadataV10 { base })
    }

    pub fn get_arb_version(&self) -> u32 {
        self.base.anti_rollback_version
    }
}

// Metadata v7 V20 224B: major,minor,arb,mrc,12soc_hw,soc_feature,jtag,8serial,oem_id,oem_pid,soc_lc,oem_lc,oem_rch_algo,oem_rch_hash,flags

#[derive(Debug, Clone)]
pub struct MetadataV20 {
    pub major_version: u32,
    pub minor_version: u32,
    pub anti_rollback_version: u32,
    pub mrc_index: u32,
    pub soc_hw_vers: Vec<u32>,
    pub soc_feature_id: u32,
    pub jtag_id: u32,
    pub serial_numbers: Vec<u64>,
    pub oem_id: u32,
    pub oem_product_id: u32,
    pub soc_lifecycle_state: u32,
    pub oem_lifecycle_state: u32,
    pub oem_root_certificate_hash_algorithm: u32,
    pub oem_root_certificate_hash: [u8; 64],
    pub flags: u32,
}

impl MetadataV20 {
    pub const SIZE: usize = 224;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 {
            return Err("Insufficient data for MetadataV20");
        }
        let mut soc_hw_vers = Vec::with_capacity(NUM_SOC_HW_VERS);
        let soc_hw_start = 16; // after major(4) + minor(4) + arb(4) + mrc(4)
        for i in 0..NUM_SOC_HW_VERS {
            let off = soc_hw_start + i * 4;
            soc_hw_vers.push(if off + 4 <= data.len() { read_le_u32(data, off) } else { 0 });
        }
        let soc_feature_off = soc_hw_start + NUM_SOC_HW_VERS * 4; // 64
        let jtag_off = soc_feature_off + 4; // 68
        let serial_start = jtag_off + 4; // 72

        let mut serial_numbers = Vec::with_capacity(NUM_SERIAL_NUMBERS);
        for i in 0..NUM_SERIAL_NUMBERS {
            let off = serial_start + i * 8;
            serial_numbers.push(if off + 8 <= data.len() { read_le_u64(data, off) } else { 0 });
        }

        let oem_fields_start = serial_start + NUM_SERIAL_NUMBERS * 8; // 136
        let hash_start = oem_fields_start + 5 * 4; // 156
        let flags_off = hash_start + 64; // 220

        let mut oem_root_certificate_hash = [0u8; 64];
        if hash_start + 64 <= data.len() {
            oem_root_certificate_hash.copy_from_slice(&data[hash_start..hash_start + 64]);
        }

        Ok(MetadataV20 {
            major_version: read_le_u32(data, 0),
            minor_version: read_le_u32(data, 4),
            anti_rollback_version: read_le_u32(data, 8),
            mrc_index: read_le_u32(data, 12),
            soc_hw_vers,
            soc_feature_id: read_opt(data, soc_feature_off),
            jtag_id: read_opt(data, jtag_off),
            serial_numbers,
            oem_id: read_opt(data, oem_fields_start),
            oem_product_id: read_opt(data, oem_fields_start + 4),
            soc_lifecycle_state: read_opt(data, oem_fields_start + 8),
            oem_lifecycle_state: read_opt(data, oem_fields_start + 12),
            oem_root_certificate_hash_algorithm: read_opt(data, oem_fields_start + 16),
            oem_root_certificate_hash,
            flags: read_opt(data, flags_off),
        })
    }

    pub fn get_arb_version(&self) -> u32 {
        self.anti_rollback_version
    }
}

fn read_opt(data: &[u8], off: usize) -> u32 {
    if off + 4 <= data.len() {
        read_le_u32(data, off)
    } else {
        0
    }
}

// V30 replaces soc_feature_id with product_segment_id

#[derive(Debug, Clone)]
pub struct MetadataV30 {
    pub base: MetadataV20,
    pub product_segment_id: u32,
}

impl MetadataV30 {
    pub const SIZE: usize = 228;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = MetadataV20::from_bytes(data)?;
        // read product_segment_id from same offset as soc_feature_id (64)
        let product_segment_id = read_opt(data, 64);
        Ok(MetadataV30 {
            base,
            product_segment_id,
        })
    }

    pub fn get_arb_version(&self) -> u32 {
        self.base.anti_rollback_version
    }
}

// V31 variant

#[derive(Debug, Clone)]
pub struct MetadataV31 {
    pub base: MetadataV30,
}

impl MetadataV31 {
    pub const SIZE: usize = 228;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = MetadataV30::from_bytes(data)?;
        Ok(MetadataV31 { base })
    }

    pub fn get_arb_version(&self) -> u32 {
        self.base.base.anti_rollback_version
    }
}

#[derive(Debug)]
pub enum Metadata {
    V00(MetadataV00),
    V10(MetadataV10),
    V20(MetadataV20),
    V30(MetadataV30),
    V31(MetadataV31),
}

impl Metadata {
    pub fn from_bytes(data: &[u8], major: u32, minor: u32) -> Result<Self, &'static str> {
        match (major, minor) {
            (0, 0) => Ok(Metadata::V00(MetadataV00::from_bytes(data)?)),
            (1, 0) => Ok(Metadata::V10(MetadataV10::from_bytes(data)?)),
            (2, 0) => Ok(Metadata::V20(MetadataV20::from_bytes(data)?)),
            (3, 0) => Ok(Metadata::V30(MetadataV30::from_bytes(data)?)),
            (3, 1) => Ok(Metadata::V31(MetadataV31::from_bytes(data)?)),
            _ => {
                if data.len() >= 12 {
                    let arb = read_le_u32(data, 8);
                    if arb <= 127 {
                        return Ok(Metadata::V20(MetadataV20 {
                            major_version: major,
                            minor_version: minor,
                            anti_rollback_version: arb,
                            mrc_index: read_opt(data, 12),
                            soc_hw_vers: Vec::new(),
                            soc_feature_id: 0,
                            jtag_id: 0,
                            serial_numbers: Vec::new(),
                            oem_id: 0,
                            oem_product_id: 0,
                            soc_lifecycle_state: 0,
                            oem_lifecycle_state: 0,
                            oem_root_certificate_hash_algorithm: 0,
                            oem_root_certificate_hash: [0; 64],
                            flags: 0,
                        }));
                    }
                }
                Err("Unknown metadata version")
            }
        }
    }

    pub fn get_arb_version(&self) -> u32 {
        match self {
            Metadata::V00(m) => m.get_arb_version(),
            Metadata::V10(m) => m.get_arb_version(),
            Metadata::V20(m) => m.get_arb_version(),
            Metadata::V30(m) => m.get_arb_version(),
            Metadata::V31(m) => m.get_arb_version(),
        }
    }

    pub fn get_version_string(&self) -> String {
        match self {
            Metadata::V00(m) => format!("{}.{}", m.major_version, m.minor_version),
            Metadata::V10(m) => format!("{}.{}", m.base.major_version, m.base.minor_version),
            Metadata::V20(m) => format!("{}.{}", m.major_version, m.minor_version),
            Metadata::V30(m) => format!("{}.{}", m.base.major_version, m.base.minor_version),
            Metadata::V31(m) => format!("{}.{}", m.base.base.major_version, m.base.base.minor_version),
        }
    }

    pub fn oem_id(&self) -> u32 {
        match self {
            Metadata::V00(m) => m.oem_id,
            Metadata::V10(m) => m.base.oem_id,
            Metadata::V20(m) => m.oem_id,
            Metadata::V30(m) => m.base.oem_id,
            Metadata::V31(m) => m.base.base.oem_id,
        }
    }

    pub fn oem_product_id(&self) -> u32 {
        match self {
            Metadata::V00(m) => m.oem_product_id,
            Metadata::V10(m) => m.base.oem_product_id,
            Metadata::V20(m) => m.oem_product_id,
            Metadata::V30(m) => m.base.oem_product_id,
            Metadata::V31(m) => m.base.base.oem_product_id,
        }
    }
}

#[derive(Debug)]
pub enum CommonMetadata {
    V00(CommonMetadataV00),
    V01(CommonMetadataV01),
}

impl CommonMetadata {
    pub fn from_bytes(data: &[u8], major: u32, minor: u32) -> Result<Self, &'static str> {
        match (major, minor) {
            (0, 0) => Ok(CommonMetadata::V00(CommonMetadataV00::from_bytes(data)?)),
            (0, 1) => Ok(CommonMetadata::V01(CommonMetadataV01::from_bytes(data)?)),
            _ => Err("Unknown common metadata version"),
        }
    }

    pub fn get_version_string(&self) -> String {
        match self {
            CommonMetadata::V00(m) => format!("{}.{}", m.major_version, m.minor_version),
            CommonMetadata::V01(m) => format!("{}.{}", m.base.major_version, m.base.minor_version),
        }
    }
}

// Helpers: build synthetic hash segment components for tests
// Not behind cfg(test) so integration tests can use them
pub fn test_common_metadata_v00(sw_id: u32, hash_algo: u32) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&0u32.to_le_bytes());  // major
    d.extend_from_slice(&0u32.to_le_bytes());  // minor
    d.extend_from_slice(&sw_id.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());  // secondary_sw_id
    d.extend_from_slice(&hash_algo.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());  // measurement_register_target
    d
}

// Build v7 V20 metadata for tests
pub fn test_metadata_v20(arb: u32, oem_id: u32, oem_pid: u32) -> Vec<u8> {
    let mut d = vec![0u8; MetadataV20::SIZE];
    d[0..4].copy_from_slice(&3u32.to_le_bytes());   // major=3
    d[4..8].copy_from_slice(&0u32.to_le_bytes());   // minor=0
    d[8..12].copy_from_slice(&arb.to_le_bytes());
    d[12..16].copy_from_slice(&0u32.to_le_bytes()); // mrc
    d[136..140].copy_from_slice(&oem_id.to_le_bytes());
    d[140..144].copy_from_slice(&oem_pid.to_le_bytes());
    d
}

// Helper: build a full v7 hash segment (40 header + 24 cm + 224 oem + hashes)
pub fn test_hash_segment_v7(arb: u32, sw_id: u32, hash_algo: u32, hash_count: usize) -> Vec<u8> {
    let hash_size = crate::hash_segment::defines::hash_algo_size(hash_algo);
    let hash_table_bytes = hash_count * hash_size;

    let mut d = Vec::new();
    // Header (40 bytes)
    d.extend_from_slice(&0u32.to_le_bytes());   // reserved
    d.extend_from_slice(&7u32.to_le_bytes());   // version
    d.extend_from_slice(&24u32.to_le_bytes());  // cm_size
    d.extend_from_slice(&0u32.to_le_bytes());   // qti_meta_size
    d.extend_from_slice(&224u32.to_le_bytes()); // oem_meta_size
    d.extend_from_slice(&(hash_table_bytes as u32).to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());   // qti_sig_size
    d.extend_from_slice(&0u32.to_le_bytes());   // qti_cert_size
    d.extend_from_slice(&0u32.to_le_bytes());   // oem_sig_size
    d.extend_from_slice(&0u32.to_le_bytes());   // oem_cert_size

    // Common metadata
    d.extend_from_slice(&test_common_metadata_v00(sw_id, hash_algo));

    // OEM metadata
    d.extend_from_slice(&test_metadata_v20(arb, 0x51, 0));

    // Hash table
    for _ in 0..hash_count {
        let mut h = vec![0u8; hash_size];
        h[0] = 0xAB;
        d.extend_from_slice(&h);
    }

    d
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- CommonMetadata ----
    #[test]
    fn test_common_metadata_v00_parse() {
        let data = test_common_metadata_v00(0x1c, 3);  // SHA384
        let cm = CommonMetadataV00::from_bytes(&data).unwrap();
        assert_eq!(cm.major_version, 0);
        assert_eq!(cm.minor_version, 0);
        assert_eq!(cm.software_id, 0x1c);
        assert_eq!(cm.secondary_software_id, 0);
        assert_eq!(cm.hash_table_algorithm, 3);
        assert_eq!(cm.measurement_register_target, 0);
    }

    #[test]
    fn test_common_metadata_v00_short_data() {
        let data = vec![0u8; 4];
        assert!(CommonMetadataV00::from_bytes(&data).is_err());
    }

    #[test]
    fn test_common_metadata_v01_zi_field() {
        let mut data = test_common_metadata_v00(0x10, 2);
        data.extend_from_slice(&4u32.to_le_bytes()); // zi algo
        let cm = CommonMetadataV01::from_bytes(&data).unwrap();
        assert_eq!(cm.base.software_id, 0x10);
        assert_eq!(cm.base.hash_table_algorithm, 2);
        assert_eq!(cm.zi_segment_hash_algorithm, 4);
    }

    #[test]
    fn test_common_metadata_enum() {
        let data = test_common_metadata_v00(0x36, 5);
        let cm = CommonMetadata::from_bytes(&data, 0, 0).unwrap();
        match cm {
            CommonMetadata::V00(m) => assert_eq!(m.software_id, 0x36),
            _ => panic!("Expected V00"),
        }
    }

    #[test]
    fn test_common_metadata_unknown_version() {
        let data = test_common_metadata_v00(0, 0);
        assert!(CommonMetadata::from_bytes(&data, 9, 9).is_err());
    }

    // ---- MetadataV20 ----
    #[test]
    fn test_metadata_v20_parse() {
        let data = test_metadata_v20(42, 0x51, 0x100);
        let meta = MetadataV20::from_bytes(&data).unwrap();
        assert_eq!(meta.major_version, 3);
        assert_eq!(meta.minor_version, 0);
        assert_eq!(meta.anti_rollback_version, 42);
        assert_eq!(meta.oem_id, 0x51);
        assert_eq!(meta.oem_product_id, 0x100);
    }

    #[test]
    fn test_metadata_v20_size() {
        let data = test_metadata_v20(0, 0, 0);
        assert_eq!(data.len(), 224);
    }

    #[test]
    fn test_metadata_v20_arb_extraction() {
        let data = test_metadata_v20(127, 0, 0);
        let meta = MetadataV20::from_bytes(&data).unwrap();
        assert_eq!(meta.get_arb_version(), 127);
    }

    // ---- MetadataV30 ----
    #[test]
    fn test_metadata_v30() {
        let mut data = test_metadata_v20(5, 0x51, 0);
        data[64..68].copy_from_slice(&77u32.to_le_bytes()); // product_segment_id
        let meta = MetadataV30::from_bytes(&data).unwrap();
        assert_eq!(meta.product_segment_id, 77);
        assert_eq!(meta.get_arb_version(), 5);
    }

    // ---- MetadataV00 (v6 format) ----
    #[test]
    fn test_metadata_v6_v00_parse() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(&0u32.to_le_bytes());   // major
        data[4..8].copy_from_slice(&0u32.to_le_bytes());   // minor
        data[8..12].copy_from_slice(&0x42u32.to_le_bytes()); // software_id
        data[116..120].copy_from_slice(&99u32.to_le_bytes()); // arb
        let meta = MetadataV00::from_bytes(&data).unwrap();
        assert_eq!(meta.software_id, 0x42);
        assert_eq!(meta.anti_rollback_version, 99);
    }

    // ---- Metadata enum ----
    #[test]
    fn test_metadata_enum_dispatch() {
        let data = test_metadata_v20(7, 0x51, 0);
        let meta = Metadata::from_bytes(&data, 3, 0).unwrap();
        assert_eq!(meta.get_arb_version(), 7);
        assert_eq!(meta.get_version_string(), "3.0");
    }

    #[test]
    fn test_metadata_enum_fallback() {
        let data = test_metadata_v20(5, 0, 0);
        let meta = Metadata::from_bytes(&data, 9, 9).unwrap();
        assert_eq!(meta.get_arb_version(), 5); // fallback reads ARB at offset 8
    }

    #[test]
    fn test_metadata_enum_unknown_high_arb() {
        // ARB=128 at offset 8 exceeds ARB_VALUE_MAX, so unknown version should error
        let mut data = vec![0u8; 32];
        data[8..12].copy_from_slice(&128u32.to_le_bytes());
        assert!(Metadata::from_bytes(&data, 9, 9).is_err());
    }

    #[test]
    fn test_metadata_enum_unknown_fallback() {
        // ARB=42 at offset 8 should trigger fallback
        let mut data = vec![0u8; 32];
        data[8..12].copy_from_slice(&42u32.to_le_bytes());
        let meta = Metadata::from_bytes(&data, 9, 9).unwrap();
        assert_eq!(meta.get_arb_version(), 42);
    }
}
