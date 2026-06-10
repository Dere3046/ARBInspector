pub mod qbec;
pub mod uie;

use crate::data::read_le_u32;
use crate::error::{Error, Result};

pub const QBEC_MAGIC: [u8; 4] = [b'C', b'E', b'B', b'Q'];
pub const UIE_MAGIC: [u8; 4] = [b'I', b'S', b'M', b'Q'];

#[derive(Debug, Clone)]
pub struct EncryptionParams {
    pub etype: EncryptionType,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum EncryptionType {
    Qbec(QbecParams),
    Uie(UieParams),
}

#[derive(Debug, Clone)]
pub struct QbecParams {
    pub version: u32,
    pub total_size: u32,
    pub key_management_parameters_size: u32,
    pub data_encryption_parameters_size: u32,
    pub encrypting_entity: u32,
    pub encryption_order: Option<u32>,
    pub key_management_scheme_id: Option<u32>,
    pub key_management_scheme_name: Option<String>,
    pub data_encryption_scheme_id: Option<u32>,
    pub data_encryption_scheme_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UieParams {
    pub num_eps: u8,
    pub eps1_offset: u16,
    pub eps1_major_version: u8,
    pub eps1_minor_version: u8,
    pub eps2_offset: u16,
    pub eps2_major_version: u8,
    pub eps2_minor_version: u8,
}

pub fn detect(data: &[u8]) -> Result<Option<EncryptionParams>> {
    if data.len() < 8 {
        return Ok(None);
    }
    if data[..4] == QBEC_MAGIC {
        let params = qbec::parse(data)?;
        Ok(Some(EncryptionParams {
            etype: EncryptionType::Qbec(params),
            raw_bytes: data.to_vec(),
        }))
    } else if data[..4] == UIE_MAGIC {
        let params = uie::parse(data)?;
        Ok(Some(EncryptionParams {
            etype: EncryptionType::Uie(params),
            raw_bytes: data.to_vec(),
        }))
    } else {
        let magic_hex = data[..4]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let version = read_le_u32(data, 4);
        Err(Error::UnknownEncryptionType { magic_hex, version })
    }
}

impl EncryptionParams {
    pub fn scheme_name(&self) -> &str {
        match &self.etype {
            EncryptionType::Qbec(p) => {
                if p.version == 1 {
                    "QBEC v1"
                } else {
                    "QBEC v2"
                }
            }
            EncryptionType::Uie(_) => "UIE",
        }
    }
}
