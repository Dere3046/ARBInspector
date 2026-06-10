use crate::config::profile::{HashAlgorithm, SecurityProfile};
use crate::config::device_restrictions::DeviceRestrictions;

pub const XBL_IMAGE_ID: u32 = 0x0010;
pub const XBL_MACHINE: u16 = 183;

pub fn default_xbl_profile() -> SecurityProfile {
    SecurityProfile::builder()
        .hash_algorithm(HashAlgorithm::Sha256)
        .build()
}

pub fn default_xbl_restrictions() -> DeviceRestrictions {
    DeviceRestrictions {
        oem_id: Some(0),
        oem_product_id: Some(0),
        anti_rollback_version: Some(0),
        ..DeviceRestrictions::default()
    }
}
