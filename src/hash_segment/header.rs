#![allow(dead_code)]

use crate::data::read_le_u32;
use crate::hash_segment::defines::{self, COMMON_SIZE_MAX, HASH_TABLE_SIZE_MAX, OEM_SIZE_MAX, QTI_SIZE_MAX, VERSION_MAX, VERSION_MIN};

#[derive(Debug, Clone)]
pub struct HashTableSegmentHeaderCommon {
    pub reserved: u32,
    pub version: u32,
}

impl HashTableSegmentHeaderCommon {
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("Insufficient data for hash table segment header");
        }
        Ok(HashTableSegmentHeaderCommon {
            reserved: read_le_u32(data, 0),
            version: read_le_u32(data, 4),
        })
    }
}

#[derive(Debug, Clone)]
pub struct HashTableSegmentHeaderV3 {
    pub reserved: u32,
    pub version: u32,
    pub hash_table_size: u32,
    pub qti_sig_size: u32,
    pub qti_cert_chain_size: u32,
    pub oem_sig_size: u32,
    pub oem_cert_chain_size: u32,
}

#[derive(Debug, Clone)]
pub struct HashTableSegmentHeaderV5 {
    pub base: HashTableSegmentHeaderV3,
    pub common_metadata_size: u32,
    pub qti_metadata_size: u32,
    pub oem_metadata_size: u32,
}

#[derive(Debug, Clone)]
pub struct HashTableSegmentHeaderV6 {
    pub base: HashTableSegmentHeaderV5,
    pub qti_sig_size: u32,
    pub qti_cert_chain_size: u32,
    pub oem_sig_size: u32,
    pub oem_cert_chain_size: u32,
    pub hash_table_size: u32,
}

#[derive(Debug, Clone)]
pub struct HashTableSegmentHeaderV7 {
    pub reserved: u32,
    pub version: u32,
    pub common_metadata_size: u32,
    pub qti_metadata_size: u32,
    pub oem_metadata_size: u32,
    pub hash_table_size: u32,
    pub qti_signature_size: u32,
    pub qti_certificate_chain_size: u32,
    pub oem_signature_size: u32,
    pub oem_certificate_chain_size: u32,
}

#[derive(Debug, Clone)]
pub struct HashTableSegmentHeaderV8 {
    pub base: HashTableSegmentHeaderV7,
    pub qti_signature_2_size: u32,
    pub qti_certificate_chain_2_size: u32,
    pub oem_signature_2_size: u32,
    pub oem_certificate_chain_2_size: u32,
}

#[derive(Debug, Clone)]
pub enum HashTableSegmentHeader {
    V3(HashTableSegmentHeaderV3),
    V5(HashTableSegmentHeaderV5),
    V6(HashTableSegmentHeaderV6),
    V7(HashTableSegmentHeaderV7),
    V8(HashTableSegmentHeaderV8),
}

fn read_v3_fields(data: &[u8], reserved: u32, version: u32) -> Result<HashTableSegmentHeaderV3, &'static str> {
    if data.len() < 28 {
        return Err("Insufficient data for HASH segment header v3");
    }
    Ok(HashTableSegmentHeaderV3 {
        reserved,
        version,
        hash_table_size: read_le_u32(data, 8),
        qti_sig_size: read_le_u32(data, 12),
        qti_cert_chain_size: read_le_u32(data, 16),
        oem_sig_size: read_le_u32(data, 20),
        oem_cert_chain_size: read_le_u32(data, 24),
    })
}

fn read_v5_fields(data: &[u8], v3: HashTableSegmentHeaderV3) -> HashTableSegmentHeaderV5 {
    HashTableSegmentHeaderV5 {
        base: v3,
        common_metadata_size: read_le_u32(data, 28),
        qti_metadata_size: read_le_u32(data, 32),
        oem_metadata_size: read_le_u32(data, 36),
    }
}

impl HashTableSegmentHeader {
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let common = HashTableSegmentHeaderCommon::from_bytes(data)?;
        match common.version {
            defines::HASH_SEGMENT_V3 => {
                let v3 = read_v3_fields(data, common.reserved, common.version)?;
                Ok(HashTableSegmentHeader::V3(v3))
            }
            defines::HASH_SEGMENT_V5 => {
                if data.len() < 40 {
                    return Err("Insufficient data for HASH segment header v5");
                }
                let v3 = read_v3_fields(data, common.reserved, common.version)?;
                let v5 = read_v5_fields(data, v3);
                Ok(HashTableSegmentHeader::V5(v5))
            }
            defines::HASH_SEGMENT_V6 => {
                if data.len() < 40 {
                    return Err("Insufficient data for HASH segment header v6");
                }
                let v3 = read_v3_fields(data, common.reserved, common.version)?;
                let v5 = read_v5_fields(data, v3);
                Ok(HashTableSegmentHeader::V6(HashTableSegmentHeaderV6 {
                    base: v5,
                    qti_sig_size: read_le_u32(data, 12),
                    qti_cert_chain_size: read_le_u32(data, 16),
                    oem_sig_size: read_le_u32(data, 20),
                    oem_cert_chain_size: read_le_u32(data, 24),
                    hash_table_size: read_le_u32(data, 8),
                }))
            }
            defines::HASH_SEGMENT_V7 => {
                if data.len() < 40 {
                    return Err("Insufficient data for HASH segment header v7");
                }
                Ok(HashTableSegmentHeader::V7(HashTableSegmentHeaderV7 {
                    reserved: common.reserved,
                    version: common.version,
                    common_metadata_size: read_le_u32(data, 8),
                    qti_metadata_size: read_le_u32(data, 12),
                    oem_metadata_size: read_le_u32(data, 16),
                    hash_table_size: read_le_u32(data, 20),
                    qti_signature_size: read_le_u32(data, 24),
                    qti_certificate_chain_size: read_le_u32(data, 28),
                    oem_signature_size: read_le_u32(data, 32),
                    oem_certificate_chain_size: read_le_u32(data, 36),
                }))
            }
            defines::HASH_SEGMENT_V8 => {
                if data.len() < 56 {
                    return Err("Insufficient data for HASH segment header v8");
                }
                let v7_base = HashTableSegmentHeaderV7 {
                    reserved: common.reserved,
                    version: common.version,
                    common_metadata_size: read_le_u32(data, 8),
                    qti_metadata_size: read_le_u32(data, 12),
                    oem_metadata_size: read_le_u32(data, 16),
                    hash_table_size: read_le_u32(data, 20),
                    qti_signature_size: read_le_u32(data, 24),
                    qti_certificate_chain_size: read_le_u32(data, 28),
                    oem_signature_size: read_le_u32(data, 32),
                    oem_certificate_chain_size: read_le_u32(data, 36),
                };
                Ok(HashTableSegmentHeader::V8(HashTableSegmentHeaderV8 {
                    base: v7_base,
                    qti_signature_2_size: read_le_u32(data, 40),
                    qti_certificate_chain_2_size: read_le_u32(data, 44),
                    oem_signature_2_size: read_le_u32(data, 48),
                    oem_certificate_chain_2_size: read_le_u32(data, 52),
                }))
            }
            _ => Err("Unknown hash table segment version"),
        }
    }

    pub fn version(&self) -> u32 {
        match self {
            HashTableSegmentHeader::V3(h) => h.version,
            HashTableSegmentHeader::V5(h) => h.base.version,
            HashTableSegmentHeader::V6(h) => h.base.base.version,
            HashTableSegmentHeader::V7(h) => h.version,
            HashTableSegmentHeader::V8(h) => h.base.version,
        }
    }

    pub fn common_metadata_size(&self) -> u32 {
        match self {
            HashTableSegmentHeader::V3(_) => 0,
            HashTableSegmentHeader::V5(h) => h.common_metadata_size,
            HashTableSegmentHeader::V6(h) => h.base.common_metadata_size,
            HashTableSegmentHeader::V7(h) => h.common_metadata_size,
            HashTableSegmentHeader::V8(h) => h.base.common_metadata_size,
        }
    }

    pub fn qti_metadata_size(&self) -> u32 {
        match self {
            HashTableSegmentHeader::V3(_) => 0,
            HashTableSegmentHeader::V5(h) => h.qti_metadata_size,
            HashTableSegmentHeader::V6(h) => h.base.qti_metadata_size,
            HashTableSegmentHeader::V7(h) => h.qti_metadata_size,
            HashTableSegmentHeader::V8(h) => h.base.qti_metadata_size,
        }
    }

    pub fn oem_metadata_size(&self) -> u32 {
        match self {
            HashTableSegmentHeader::V3(_) => 0,
            HashTableSegmentHeader::V5(h) => h.oem_metadata_size,
            HashTableSegmentHeader::V6(h) => h.base.oem_metadata_size,
            HashTableSegmentHeader::V7(h) => h.oem_metadata_size,
            HashTableSegmentHeader::V8(h) => h.base.oem_metadata_size,
        }
    }

    pub fn hash_table_size(&self) -> u32 {
        match self {
            HashTableSegmentHeader::V3(h) => h.hash_table_size,
            HashTableSegmentHeader::V5(h) => h.base.hash_table_size,
            HashTableSegmentHeader::V6(h) => h.base.base.hash_table_size,
            HashTableSegmentHeader::V7(h) => h.hash_table_size,
            HashTableSegmentHeader::V8(h) => h.base.hash_table_size,
        }
    }

    pub fn qti_signature_size(&self) -> u32 {
        match self {
            HashTableSegmentHeader::V3(h) => h.qti_sig_size,
            HashTableSegmentHeader::V5(h) => h.base.qti_sig_size,
            HashTableSegmentHeader::V6(h) => h.qti_sig_size,
            HashTableSegmentHeader::V7(h) => h.qti_signature_size,
            HashTableSegmentHeader::V8(h) => h.base.qti_signature_size,
        }
    }

    pub fn qti_certificate_chain_size(&self) -> u32 {
        match self {
            HashTableSegmentHeader::V3(h) => h.qti_cert_chain_size,
            HashTableSegmentHeader::V5(h) => h.base.qti_cert_chain_size,
            HashTableSegmentHeader::V6(h) => h.qti_cert_chain_size,
            HashTableSegmentHeader::V7(h) => h.qti_certificate_chain_size,
            HashTableSegmentHeader::V8(h) => h.base.qti_certificate_chain_size,
        }
    }

    pub fn oem_signature_size(&self) -> u32 {
        match self {
            HashTableSegmentHeader::V3(h) => h.oem_sig_size,
            HashTableSegmentHeader::V5(h) => h.base.oem_sig_size,
            HashTableSegmentHeader::V6(h) => h.oem_sig_size,
            HashTableSegmentHeader::V7(h) => h.oem_signature_size,
            HashTableSegmentHeader::V8(h) => h.base.oem_signature_size,
        }
    }

    pub fn oem_certificate_chain_size(&self) -> u32 {
        match self {
            HashTableSegmentHeader::V3(h) => h.oem_cert_chain_size,
            HashTableSegmentHeader::V5(h) => h.base.oem_cert_chain_size,
            HashTableSegmentHeader::V6(h) => h.oem_cert_chain_size,
            HashTableSegmentHeader::V7(h) => h.oem_certificate_chain_size,
            HashTableSegmentHeader::V8(h) => h.base.oem_certificate_chain_size,
        }
    }

    pub fn is_plausible(&self) -> bool {
        let version = self.version();
        let common_sz = self.common_metadata_size() as usize;
        let qti_sz = self.qti_metadata_size() as usize;
        let oem_sz = self.oem_metadata_size() as usize;
        let hash_sz = self.hash_table_size() as usize;

        (VERSION_MIN..=VERSION_MAX).contains(&version)
            && common_sz <= COMMON_SIZE_MAX
            && qti_sz <= QTI_SIZE_MAX
            && oem_sz <= OEM_SIZE_MAX
            && hash_sz > 0
            && hash_sz <= HASH_TABLE_SIZE_MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_v7_header_bytes(cm: u32, oem: u32, hash: u32) -> Vec<u8> {
        let mut d = vec![0u8; 40];
        d[4..8].copy_from_slice(&7u32.to_le_bytes());    // version
        d[8..12].copy_from_slice(&cm.to_le_bytes());     // cm_size
        d[16..20].copy_from_slice(&oem.to_le_bytes());   // oem_size
        d[20..24].copy_from_slice(&hash.to_le_bytes());  // hash_table_size
        d
    }

    fn make_v8_header_bytes(hash: u32) -> Vec<u8> {
        let mut d = vec![0u8; 56];
        d[4..8].copy_from_slice(&8u32.to_le_bytes());     // version
        d[20..24].copy_from_slice(&hash.to_le_bytes());   // hash_table_size
        d
    }

    #[test]
    fn test_v7_header_parse() {
        let data = make_v7_header_bytes(24, 224, 384);
        let hdr = HashTableSegmentHeader::from_bytes(&data).unwrap();
        assert_eq!(hdr.version(), 7);
        assert_eq!(hdr.common_metadata_size(), 24);
        assert_eq!(hdr.oem_metadata_size(), 224);
        assert_eq!(hdr.hash_table_size(), 384);
    }

    #[test]
    fn test_v8_header_parse() {
        let data = make_v8_header_bytes(432);
        let hdr = HashTableSegmentHeader::from_bytes(&data).unwrap();
        assert_eq!(hdr.version(), 8);
        assert_eq!(hdr.hash_table_size(), 432);
    }

    #[test]
    fn test_v7_header_plausible() {
        let data = make_v7_header_bytes(24, 224, 64);
        let hdr = HashTableSegmentHeader::from_bytes(&data).unwrap();
        assert!(hdr.is_plausible());
    }

    #[test]
    fn test_v7_header_implausible_zero_hash() {
        let data = make_v7_header_bytes(24, 224, 0);
        let hdr = HashTableSegmentHeader::from_bytes(&data).unwrap();
        assert!(!hdr.is_plausible());
    }

    #[test]
    fn test_v7_header_implausible_oversized() {
        let data = make_v7_header_bytes(24, 224, 0x20000);
        let hdr = HashTableSegmentHeader::from_bytes(&data).unwrap();
        assert!(!hdr.is_plausible());
    }

    #[test]
    fn test_v7_header_fields() {
        let mut data = make_v7_header_bytes(24, 224, 144);
        data[12..16].copy_from_slice(&224u32.to_le_bytes()); // qti_meta_size
        data[24..28].copy_from_slice(&102u32.to_le_bytes()); // qti_sig_size
        data[28..32].copy_from_slice(&1472u32.to_le_bytes());// qti_cert_size
        data[32..36].copy_from_slice(&104u32.to_le_bytes()); // oem_sig_size
        data[36..40].copy_from_slice(&3360u32.to_le_bytes());// oem_cert_size

        let hdr = HashTableSegmentHeader::from_bytes(&data).unwrap();
        assert_eq!(hdr.qti_metadata_size(), 224);
        assert_eq!(hdr.qti_signature_size(), 102);
        assert_eq!(hdr.qti_certificate_chain_size(), 1472);
        assert_eq!(hdr.oem_signature_size(), 104);
        assert_eq!(hdr.oem_certificate_chain_size(), 3360);
    }

    #[test]
    fn test_v3_v5_v6_header_parse() {
        for ver in [3u32, 5, 6] {
            let mut d = vec![0u8; 40];
            d[4..8].copy_from_slice(&ver.to_le_bytes());
            d[8..12].copy_from_slice(&64u32.to_le_bytes()); // hash table size at offset 8 for v3/v5/v6
            let hdr = HashTableSegmentHeader::from_bytes(&d).unwrap();
            assert_eq!(hdr.version(), ver);
            assert!(hdr.is_plausible());
        }
    }

    #[test]
    fn test_unknown_version() {
        let mut d = vec![0u8; 40];
        d[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(HashTableSegmentHeader::from_bytes(&d).is_err());
    }

    #[test]
    fn test_short_data() {
        assert!(HashTableSegmentHeader::from_bytes(&[0u8; 4]).is_err());
    }
}
