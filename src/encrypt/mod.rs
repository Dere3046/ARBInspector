pub mod qbec;
pub mod uie;

use crate::error::Result;

pub fn generate_encryption_params(
    etype: &str,
    version: u32,
    entity: u32,
    order: u32,
) -> Result<crate::hash_segment::encryption::EncryptionParams> {
    match etype {
        "qbec" | "QBEC" => qbec::generate(version, entity, order),
        "uie" | "UIE" => {
            let _ = (version, entity, order);
            uie::generate()
        }
        _ => Err(crate::error::Error::UnsupportedEncryptionScheme(
            etype.into(),
        )),
    }
}

pub fn serialize(
    params: &crate::hash_segment::encryption::EncryptionParams,
) -> Vec<u8> {
    match &params.etype {
        crate::hash_segment::encryption::EncryptionType::Qbec(q) => {
            qbec::serialize_to_bytes(q)
        }
        crate::hash_segment::encryption::EncryptionType::Uie(u) => {
            uie::serialize_to_bytes(u)
        }
    }
}
