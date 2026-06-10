use crate::data::read_le_u32;
use crate::error::{Error, Result};
use crate::hash_segment::encryption::QBEC_MAGIC;

#[rustfmt::skip]
const KEY_MGMT_SCHEME_NAMES: [(&str, u32); 6] = [
    ("ECDH-P384-HKDF-SIV-GCM",      0),
    ("ECDH-P384-HKDF-SIV-XTS",      1),
    ("ECDH-P384-HKDF-SIV-GCM-2",    2),
    ("ECDH-P384-HKDF-SIV-64-GCM",   3),
    ("ECDH-P384-HKDF-SIV-CMAC-GCM", 4),
    ("GCM-GCM",                     5),
];

#[rustfmt::skip]
const DATA_ENC_SCHEME_NAMES: [(&str, u32); 2] = [
    ("ELF-SEGMENT-AES-GCM", 0),
    ("AES-128-XTS",         1),
];

const ENCRYPTING_ENTITY_NAMES: [(&str, u32); 3] = [
    ("QTI", 0),
    ("OEM", 1),
    ("ISV", 2),
];

pub fn key_mgmt_scheme_name(id: u32) -> Option<&'static str> {
    KEY_MGMT_SCHEME_NAMES
        .iter()
        .find(|(_, v)| *v == id)
        .map(|(n, _)| *n)
}

pub fn data_enc_scheme_name(id: u32) -> Option<&'static str> {
    DATA_ENC_SCHEME_NAMES
        .iter()
        .find(|(_, v)| *v == id)
        .map(|(n, _)| *n)
}

fn encrypting_entity_name(id: u32) -> Option<&'static str> {
    ENCRYPTING_ENTITY_NAMES
        .iter()
        .find(|(_, v)| *v == id)
        .map(|(n, _)| *n)
}

use crate::hash_segment::encryption::QbecParams;

pub fn parse(data: &[u8]) -> Result<QbecParams> {
    if data.len() < 8 {
        return Err(Error::EncryptionParamParse(
            "QBEC data too short for header".into(),
        ));
    }

    if &data[..4] != QBEC_MAGIC {
        return Err(Error::EncryptionParamParse(
            "QBEC magic not found".into(),
        ));
    }

    let version = read_le_u32(data, 4);

    let (total_size, km_size, de_size, encrypting_entity, encryption_order) = match version {
        1 => {
            if data.len() < 24 {
                return Err(Error::EncryptionParamParse(format!(
                    "QBEC v1 header too short: {} bytes, need 24",
                    data.len()
                )));
            }
            let total_size = read_le_u32(data, 8);
            let km_size = read_le_u32(data, 12);
            let de_size = read_le_u32(data, 16);
            let entity = read_le_u32(data, 20);
            (total_size, km_size, de_size, entity, None)
        }
        2 => {
            if data.len() < 28 {
                return Err(Error::EncryptionParamParse(format!(
                    "QBEC v2 header too short: {} bytes, need 28",
                    data.len()
                )));
            }
            let total_size = read_le_u32(data, 8);
            let km_size = read_le_u32(data, 12);
            let de_size = read_le_u32(data, 16);
            let entity = read_le_u32(data, 20);
            let order = read_le_u32(data, 24);
            (total_size, km_size, de_size, entity, Some(order))
        }
        _ => {
            return Err(Error::UnsupportedEncryptionScheme(format!(
                "QBEC version {}",
                version
            )));
        }
    };

    let (key_mgmt_scheme_id, key_mgmt_scheme_name) = if km_size > 0 {
        let km_offset = match version {
            1 => 24usize,
            2 => 28usize,
            _ => unreachable!(),
        };
        if km_offset + 4 <= data.len() {
            let scheme_id = read_le_u32(data, km_offset);
            (Some(scheme_id), key_mgmt_scheme_name(scheme_id).map(|s| s.to_string()))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let (data_enc_scheme_id, data_enc_scheme_name) = if de_size > 0 {
        let de_offset = match version {
            1 => 24usize + km_size as usize,
            2 => 28usize + km_size as usize,
            _ => unreachable!(),
        };
        if de_offset + 4 <= data.len() {
            let scheme_id = read_le_u32(data, de_offset);
            (Some(scheme_id), data_enc_scheme_name(scheme_id).map(|s| s.to_string()))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    Ok(QbecParams {
        version,
        total_size,
        key_management_parameters_size: km_size,
        data_encryption_parameters_size: de_size,
        encrypting_entity,
        encryption_order,
        key_management_scheme_id: key_mgmt_scheme_id,
        key_management_scheme_name: key_mgmt_scheme_name,
        data_encryption_scheme_id: data_enc_scheme_id,
        data_encryption_scheme_name: data_enc_scheme_name,
    })
}

pub fn encrypting_entity_str(id: u32) -> &'static str {
    encrypting_entity_name(id).unwrap_or("Unknown")
}

pub fn encryption_order_str(order: u32) -> &'static str {
    match order {
        0 => "Encrypted then Signed",
        1 => "Signed then Encrypted",
        _ => "Unknown",
    }
}
