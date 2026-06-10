#[derive(Debug, Clone, Default)]
pub struct DeviceRestrictions {
    pub oem_id: Option<u32>,
    pub oem_product_id: Option<u32>,
    pub anti_rollback_version: Option<u32>,
    pub serial_number: Option<u32>,
    pub soc_hw_vers: Option<Vec<u32>>,
    pub soc_feature_id: Option<u32>,
    pub jtag_id: Option<u32>,
    pub soc_lifecycle_state: Option<u32>,
    pub oem_lifecycle_state: Option<u32>,
    pub mrc_index: Option<u32>,
    pub debug: Option<u32>,
    pub secondary_software_id: Option<u32>,
    pub flags: Option<u32>,
}

impl DeviceRestrictions {
    pub fn new() -> Self {
        DeviceRestrictions::default()
    }

    pub fn apply_to_metadata_v20(&self, meta: &mut crate::hash_segment::metadata::MetadataV20) {
        if let Some(v) = self.oem_id { meta.oem_id = v; }
        if let Some(v) = self.oem_product_id { meta.oem_product_id = v; }
        if let Some(v) = self.anti_rollback_version { meta.anti_rollback_version = v; }
        if let Some(v) = self.mrc_index { meta.mrc_index = v; }
        if let Some(v) = self.soc_feature_id { meta.soc_feature_id = v; }
        if let Some(v) = self.jtag_id { meta.jtag_id = v; }
        if let Some(v) = self.soc_lifecycle_state { meta.soc_lifecycle_state = v; }
        if let Some(v) = self.oem_lifecycle_state { meta.oem_lifecycle_state = v; }
        if let Some(v) = self.flags { meta.flags = v; }
    }
}
