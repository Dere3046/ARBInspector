use crate::elf::parser::ElfParser;
use crate::error::{Error, Result};
use crate::hash_segment::parser::HashSegmentInfo;

#[derive(Debug, Clone)]
pub struct SecELF {
    pub data: Vec<u8>,
    pub oem_id: u32,
    pub oem_product_id: u32,
}

#[derive(Debug, Clone)]
pub struct SecDat {
    pub header: SecDatHeader,
    pub segments: Vec<SecDatSegment>,
}

#[derive(Debug, Clone)]
pub struct SecDatHeader {
    pub version: u32,
    pub num_segments: u32,
}

#[derive(Debug, Clone)]
pub struct SecDatSegment {
    pub data: Vec<u8>,
}

impl SecELF {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let parser = ElfParser::from_bytes(data)
            .map_err(|e| Error::ElfParse(format!("not a valid ELF: {}", e)))?;

        let (oem_id, oem_product_id) = parser
            .find_hash_segment()
            .and_then(|phdr| {
                let offset = phdr.p_offset as usize;
                HashSegmentInfo::parse(data, offset).ok()?
            })
            .and_then(|info| info.oem_metadata)
            .map(|meta| (meta.oem_id(), meta.oem_product_id()))
            .unwrap_or((0, 0));

        Ok(SecELF {
            data: data.to_vec(),
            oem_id,
            oem_product_id,
        })
    }
}

impl SecDat {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(Error::Custom(format!(
                "SecDat too short: {} bytes, need at least 8 for header",
                data.len()
            )));
        }
        let version = u32::from_le_bytes(data[..4].try_into().unwrap());
        let num_segments = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let mut segments = Vec::new();
        let mut offset = 8usize;
        for i in 0..num_segments {
            if offset + 8 > data.len() {
                return Err(Error::Custom(format!(
                    "SecDat segment {} header truncated at offset {}",
                    i, offset
                )));
            }
            let seg_size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            let _flags = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
            offset += 8;
            let end = offset + seg_size;
            if end > data.len() {
                return Err(Error::Custom(format!(
                    "SecDat segment {} data truncated: declared size {} but only {} bytes remain",
                    i,
                    seg_size,
                    data.len() - offset
                )));
            }
            segments.push(SecDatSegment {
                data: data[offset..end].to_vec(),
            });
            offset = end;
        }
        Ok(SecDat {
            header: SecDatHeader {
                version,
                num_segments,
            },
            segments,
        })
    }
}

pub fn cross_validate_oem_id(image_oem_id: u32, fuse_oem_id: u32) -> Result<()> {
    if image_oem_id != fuse_oem_id {
        return Err(Error::Custom(format!(
            "OEM ID mismatch: image=0x{:08X}, fuse=0x{:08X}",
            image_oem_id, fuse_oem_id
        )));
    }
    Ok(())
}
