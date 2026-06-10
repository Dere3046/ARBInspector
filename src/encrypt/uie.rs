use crate::error::Result;
use crate::hash_segment::encryption::{EncryptionParams, EncryptionType, UieParams};

const UIE_HEADER_SIZE: usize = 20;

pub fn generate() -> Result<EncryptionParams> {
    let u = UieParams {
        num_eps: 1,
        eps1_offset: UIE_HEADER_SIZE as u16,
        eps1_major_version: 1,
        eps1_minor_version: 0,
        eps2_offset: 0,
        eps2_major_version: 0,
        eps2_minor_version: 0,
    };

    Ok(EncryptionParams {
        etype: EncryptionType::Uie(u),
        raw_bytes: Vec::new(),
    })
}

pub fn serialize_to_bytes(u: &UieParams) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"ISMQ");
    out.push(u.num_eps);
    out.extend_from_slice(&[0u8; 3]); // reserved
    out.extend_from_slice(&(u.eps1_offset as u32).to_le_bytes());
    out.push(u.eps1_major_version);
    out.push(u.eps1_minor_version);
    out.extend_from_slice(&(u.eps2_offset as u32).to_le_bytes());
    out.push(u.eps2_major_version);
    out.push(u.eps2_minor_version);
    out
}
