use crate::error::{Error, Result};
use crate::hash_segment::encryption::{EncryptionParams, EncryptionType, QbecParams};

/// Generate QBEC v1 encryption parameters with Encrypt-then-Sign ordering.
pub fn generate_v1(entity: u32) -> Result<EncryptionParams> {
    let km_size = KEY_MGMT_HDR_SIZE;
    let de_size = DATA_ENC_HDR_SIZE;
    let total = QBEC_V1_HDR_SIZE + km_size + de_size;

    let q = QbecParams {
        version: 1,
        total_size: total as u32,
        key_management_parameters_size: km_size as u32,
        data_encryption_parameters_size: de_size as u32,
        encrypting_entity: entity,
        encryption_order: None,
        key_management_scheme_id: Some(0),
        key_management_scheme_name: Some("ECDH-P384-HKDF-SIV-GCM".into()),
        data_encryption_scheme_id: Some(0),
        data_encryption_scheme_name: Some("ELF-SEGMENT-AES-GCM".into()),
    };

    Ok(EncryptionParams {
        etype: EncryptionType::Qbec(q),
        raw_bytes: Vec::new(),
    })
}

/// Generate QBEC v2 encryption parameters with configurable encryption order.
pub fn generate_v2(entity: u32, order: u32) -> Result<EncryptionParams> {
    let km_size = KEY_MGMT_HDR_SIZE;
    let de_size = DATA_ENC_HDR_SIZE;
    let total = QBEC_V2_HDR_SIZE + km_size + de_size;

    let q = QbecParams {
        version: 2,
        total_size: total as u32,
        key_management_parameters_size: km_size as u32,
        data_encryption_parameters_size: de_size as u32,
        encrypting_entity: entity,
        encryption_order: Some(order),
        key_management_scheme_id: Some(1),
        key_management_scheme_name: Some("ECDH-P384-HKDF-SIV-XTS".into()),
        data_encryption_scheme_id: Some(1),
        data_encryption_scheme_name: Some("AES-128-XTS".into()),
    };

    Ok(EncryptionParams {
        etype: EncryptionType::Qbec(q),
        raw_bytes: Vec::new(),
    })
}

pub fn generate(version: u32, entity: u32, order: u32) -> Result<EncryptionParams> {
    match version {
        1 => generate_v1(entity),
        2 => generate_v2(entity, order),
        _ => Err(Error::UnsupportedEncryptionScheme(format!(
            "QBEC version {}",
            version
        ))),
    }
}

pub const QBEC_V1_HDR_SIZE: usize = 24;
pub const QBEC_V2_HDR_SIZE: usize = 28;
pub const KEY_MGMT_HDR_SIZE: usize = 8;
pub const DATA_ENC_HDR_SIZE: usize = 8;

/// Serialize QBEC params to bytes (header + parameter stubs).
pub fn serialize_to_bytes(q: &QbecParams) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"CEBQ");
    out.extend_from_slice(&q.version.to_le_bytes());
    out.extend_from_slice(&q.total_size.to_le_bytes());
    out.extend_from_slice(&q.key_management_parameters_size.to_le_bytes());
    out.extend_from_slice(&q.data_encryption_parameters_size.to_le_bytes());
    out.extend_from_slice(&q.encrypting_entity.to_le_bytes());
    if q.version >= 2 {
        out.extend_from_slice(&q.encryption_order.unwrap_or(0).to_le_bytes());
    }
    out
}
