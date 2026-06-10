use crate::data::read_le_u32;
use crate::error::{Error, Result};
use crate::hash_segment::defines::{self, SHA256_SIZE};
use crate::hash_segment::encryption::{self, EncryptionParams};
use crate::hash_segment::header::HashTableSegmentHeader;
use crate::hash_segment::metadata::{CommonMetadata, Metadata};

#[derive(Debug)]
pub struct HashSegmentInfo {
    pub header: HashTableSegmentHeader,
    pub common_metadata: Option<CommonMetadata>,
    pub oem_metadata: Option<Metadata>,
    pub qti_metadata: Option<Metadata>,
    pub serial_num: Option<u32>,
    pub hashes: Vec<Vec<u8>>,
    pub encryption: Option<EncryptionParams>,
}

impl HashSegmentInfo {
    pub fn parse(data: &[u8], hash_offset: usize) -> Result<Option<Self>> {
        let remaining = &data[hash_offset..];
        if remaining.len() < 40 {
            return Ok(None);
        }

        let header = HashTableSegmentHeader::from_bytes(remaining)
            .map_err(|e| Error::HashSegmentParse(format!("failed to parse hash segment header: {}", e)))?;

        if !header.is_plausible() {
            return Ok(None);
        }

        let hdr_size = defines::hash_table_header_size(header.version());
        let mut offset = hdr_size;

        let common_metadata = Self::parse_common_metadata(remaining, &mut offset, header.common_metadata_size())?;
        let qti_metadata = Self::parse_metadata(remaining, &mut offset, header.qti_metadata_size())?;
        let oem_metadata = Self::parse_metadata(remaining, &mut offset, header.oem_metadata_size())?;

        let hash_algo = common_metadata.as_ref().map_or(2, |cm| match cm {
            CommonMetadata::V00(m) => m.hash_table_algorithm,
            CommonMetadata::V01(m) => m.base.hash_table_algorithm,
        });
        let hash_size = defines::hash_algo_size(hash_algo);

        let hash_table_offset = offset;
        let hash_table_size = header.hash_table_size() as usize;
        let (serial_num, hashes) = if hash_table_offset + hash_table_size <= remaining.len()
            && hash_table_size > 0
        {
            let hash_table = &remaining[hash_table_offset..hash_table_offset + hash_table_size];
            Self::parse_hash_table(hash_table, hash_size)
        } else {
            (None, Vec::new())
        };
        offset = hash_table_offset + hash_table_size;

        let encryption = Self::parse_remaining(remaining, &mut offset, &header)?;

        Ok(Some(HashSegmentInfo {
            header,
            common_metadata,
            oem_metadata,
            qti_metadata,
            serial_num,
            hashes,
            encryption,
        }))
    }

    fn parse_common_metadata(
        data: &[u8],
        offset: &mut usize,
        size: u32,
    ) -> std::result::Result<Option<CommonMetadata>, &'static str> {
        if size == 0 {
            return Ok(None);
        }
        let sz = size as usize;
        if *offset + sz > data.len() {
            return Ok(None);
        }
        let cm_data = &data[*offset..*offset + sz];
        *offset += sz;

        if cm_data.len() < 8 {
            return Ok(None);
        }
        let cm_major = read_le_u32(cm_data, 0);
        let cm_minor = read_le_u32(cm_data, 4);
        match CommonMetadata::from_bytes(cm_data, cm_major, cm_minor) {
            Ok(cm) => Ok(Some(cm)),
            Err(_) => Ok(None),
        }
    }

    fn parse_metadata(
        data: &[u8],
        offset: &mut usize,
        size: u32,
    ) -> Result<Option<Metadata>> {
        if size == 0 {
            return Ok(None);
        }
        let sz = size as usize;
        if *offset + sz > data.len() {
            return Ok(None);
        }
        let meta_data = &data[*offset..*offset + sz];
        *offset += sz;

        if meta_data.len() < 12 {
            return Ok(None);
        }
        let major = read_le_u32(meta_data, 0);
        let minor = read_le_u32(meta_data, 4);

        match Metadata::from_bytes(meta_data, major, minor) {
            Ok(m) => Ok(Some(m)),
            Err(_) => Ok(None),
        }
    }

    fn parse_hash_table(data: &[u8], hash_size: usize) -> (Option<u32>, Vec<Vec<u8>>) {
        let mut serial_num = None;
        let mut hashes = Vec::new();

        if data.len() >= hash_size * 2 {
            let potential_serial = read_le_u32(data, hash_size);
            let first_hash_all_zero = data[..hash_size].iter().all(|&b| b == 0);
            if first_hash_all_zero && potential_serial != 0 {
                serial_num = Some(potential_serial);
                let mut ht_offset = hash_size * 2;
                while ht_offset + hash_size <= data.len() {
                    hashes.push(data[ht_offset..ht_offset + hash_size].to_vec());
                    ht_offset += hash_size;
                }
            }
        }

        if serial_num.is_none() {
            let mut ht_offset = 0;
            while ht_offset + hash_size <= data.len() {
                hashes.push(data[ht_offset..ht_offset + hash_size].to_vec());
                ht_offset += hash_size;
            }
        }

        (serial_num, hashes)
    }

    fn parse_remaining(
        data: &[u8],
        offset: &mut usize,
        header: &HashTableSegmentHeader,
    ) -> Result<Option<EncryptionParams>> {
        let sig_qti_size = header.qti_signature_size() as usize;
        let cert_qti_size = header.qti_certificate_chain_size() as usize;
        let sig_oem_size = header.oem_signature_size() as usize;
        let cert_oem_size = header.oem_certificate_chain_size() as usize;

        let total_after_hash = sig_qti_size + cert_qti_size + sig_oem_size + cert_oem_size;

        *offset += total_after_hash;
        if *offset >= data.len() {
            return Ok(None);
        }

        let remaining = &data[*offset..];

        if remaining.len() < 8 {
            return Ok(None);
        }

        // Check for padding (0x00 or 0xFF filled)
        let first4 = &remaining[..4];
        if first4 == &[0u8; 4] || first4 == &[0xFFu8; 4] {
            return Ok(None);
        }

        match encryption::detect(remaining) {
            Ok(Some(params)) => {
                if let EncryptionParams {
                    etype: crate::hash_segment::encryption::EncryptionType::Qbec(ref q),
                    ..
                } = params
                {
                    if q.encryption_order == Some(1) {
                        return Err(Error::SignThenEncryptDetected);
                    }
                }
                Ok(Some(params))
            }
            Ok(None) => Ok(None),
            Err(_) => Ok(None),
        }
    }

    pub fn get_arb_version(&self) -> Option<u32> {
        self.oem_metadata.as_ref().map(|m| m.get_arb_version())
    }

    pub fn is_qti_signed(&self) -> bool {
        self.header.qti_signature_size() > 0
    }

    pub fn is_oem_signed(&self) -> bool {
        self.header.oem_signature_size() > 0
    }

    pub fn is_signed(&self) -> bool {
        self.is_qti_signed() || self.is_oem_signed()
    }

    pub fn signature_status(&self) -> SignatureStatus {
        match (self.is_qti_signed(), self.is_oem_signed()) {
            (true, true) => SignatureStatus::Both,
            (true, false) => SignatureStatus::QtiOnly,
            (false, true) => SignatureStatus::OemOnly,
            (false, false) => SignatureStatus::Unsigned,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    Unsigned,
    QtiOnly,
    OemOnly,
    Both,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_v7_hash_segment() {
        let hs = crate::hash_segment::metadata::test_hash_segment_v7(42, 0x1c, 3, 8);
        let result = HashSegmentInfo::parse(&hs, 0).unwrap();
        assert!(result.is_some());
        let info = result.unwrap();

        assert_eq!(info.header.version(), 7);
        assert_eq!(info.get_arb_version(), Some(42));
        assert_eq!(info.hashes.len(), 8);
        assert_eq!(info.hashes[0].len(), 48); // SHA384
        assert!(!info.is_signed());
    }

    #[test]
    fn test_parse_v7_with_signature() {
        let mut hs = crate::hash_segment::metadata::test_hash_segment_v7(7, 0x36, 3, 4);
        // Update header to indicate presence of QTI signature
        hs[24..28].copy_from_slice(&102u32.to_le_bytes());  // qti_sig_size
        hs[28..32].copy_from_slice(&1472u32.to_le_bytes()); // qti_cert_size
        // Append dummy sig + cert data
        hs.extend_from_slice(&[0xAAu8; 102]);
        hs.extend_from_slice(&[0xBBu8; 1472]);

        let info = HashSegmentInfo::parse(&hs, 0).unwrap().unwrap();
        assert!(info.is_qti_signed());
        assert!(!info.is_oem_signed());
        assert!(info.is_signed());
        assert_eq!(info.signature_status(), SignatureStatus::QtiOnly);
    }

    #[test]
    fn test_parse_v7_both_signatures() {
        let mut hs = crate::hash_segment::metadata::test_hash_segment_v7(0, 0, 2, 2);
        hs[24..28].copy_from_slice(&100u32.to_le_bytes());
        hs[28..32].copy_from_slice(&500u32.to_le_bytes());
        hs[32..36].copy_from_slice(&100u32.to_le_bytes());
        hs[36..40].copy_from_slice(&500u32.to_le_bytes());
        hs.extend_from_slice(&[0xCCu8; 100]); // qti sig
        hs.extend_from_slice(&[0xDDu8; 500]); // qti cert
        hs.extend_from_slice(&[0xEEu8; 100]); // oem sig
        hs.extend_from_slice(&[0xFFu8; 500]); // oem cert

        let info = HashSegmentInfo::parse(&hs, 0).unwrap().unwrap();
        assert_eq!(info.signature_status(), SignatureStatus::Both);
    }

    #[test]
    fn test_parse_short_buffer() {
        let result = HashSegmentInfo::parse(&[0u8; 4], 0).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_implausible_header() {
        // v7 header with hash_size=0 should be implausible
        let mut hs = crate::hash_segment::metadata::test_hash_segment_v7(0, 0, 2, 0);
        // Set hash_table_size to 0 in the header
        hs[20..24].copy_from_slice(&0u32.to_le_bytes());
        let result = HashSegmentInfo::parse(&hs, 0).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_arb_without_oem_metadata() {
        let mut data = vec![0u8; 40];
        data[4..8].copy_from_slice(&7u32.to_le_bytes());   // version
        data[8..12].copy_from_slice(&0u32.to_le_bytes());  // cm_size=0
        data[16..20].copy_from_slice(&0u32.to_le_bytes()); // oem_size=0
        data[20..24].copy_from_slice(&64u32.to_le_bytes()); // hash_size
        data.extend_from_slice(&[0u8; 64]);                 // dummy hashes

        let info = HashSegmentInfo::parse(&data, 0).unwrap().unwrap();
        assert_eq!(info.get_arb_version(), None);
    }

    #[test]
    fn test_parse_with_qti_metadata() {
        let mut hs = crate::hash_segment::metadata::test_hash_segment_v7(10, 0x42, 2, 3);
        // Add QTI metadata (224 bytes, same format as OEM)
        let qti = crate::hash_segment::metadata::test_metadata_v20(99, 0, 0);
        // Update header for qti_meta_size
        hs[12..16].copy_from_slice(&224u32.to_le_bytes());
        // Insert qti metadata after common metadata (at offset 40+24=64)
        let pos = 40 + 24;
        let mut new_hs = Vec::new();
        new_hs.extend_from_slice(&hs[..pos]);
        new_hs.extend_from_slice(&qti);           // 224 bytes QTI metadata
        new_hs.extend_from_slice(&hs[pos..]);     // OEM metadata + hashes
        let info = HashSegmentInfo::parse(&new_hs, 0).unwrap().unwrap();
        assert_eq!(info.get_arb_version(), Some(10)); // OEM ARB still used
    }
}
