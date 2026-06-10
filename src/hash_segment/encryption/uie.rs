use crate::data::read_le_u32;
use crate::error::{Error, Result};
use crate::hash_segment::encryption::UIE_MAGIC;

use crate::hash_segment::encryption::UieParams;

pub fn parse(data: &[u8]) -> Result<UieParams> {
    if data.len() < 16 {
        return Err(Error::EncryptionParamParse(format!(
            "UIE data too short for info header: {} bytes, need 16",
            data.len()
        )));
    }

    if &data[..4] != UIE_MAGIC {
        return Err(Error::EncryptionParamParse(
            "UIE magic not found".into(),
        ));
    }

    let num_eps = data[4];
    let _reserved_0 = data[5];
    let _reserved_1 = data[6];
    let _reserved_2 = data[7];

    let eps1_offset = read_le_u32(data, 8) as u16;
    let eps1_major_version = data[12];
    let eps1_minor_version = data[13];
    let eps2_offset = read_le_u32(data, 14) as u16;
    let eps2_major_version = data[18];
    let eps2_minor_version = data[19];

    Ok(UieParams {
        num_eps,
        eps1_offset,
        eps1_major_version,
        eps1_minor_version,
        eps2_offset,
        eps2_major_version,
        eps2_minor_version,
    })
}
