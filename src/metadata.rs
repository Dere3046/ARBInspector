#![allow(dead_code)]

#[inline]
fn read_le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off+2].try_into().unwrap())
}

#[inline]
fn read_le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off+4].try_into().unwrap())
}

#[inline]
fn read_le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off+8].try_into().unwrap())
}

#[derive(Debug, Clone)]
pub struct MetadataV00 {
    pub major_version: u32,
    pub minor_version: u32,
    pub software_id: u32,
    pub soc_hw_vers: [u32; 32],
    pub jtag_id: u64,
    pub serial_numbers: [u32; 8],
    pub oem_id: u32,
    pub oem_product_id: u32,
    pub anti_rollback_version: u32,
    pub mrc_index: u32,
    pub debug: u32,
    pub secondary_software_id: u32,
    pub flags: u32,
}

impl MetadataV00 {
    pub const SIZE: usize = 208;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::SIZE {
            return Err("Insufficient data for MetadataV00");
        }
        let mut soc_hw_vers = [0u32; 32];
        let mut serial_numbers = [0u32; 8];
        for i in 0..32 {
            soc_hw_vers[i] = read_le_u32(data, 8 + i * 4);
        }
        for i in 0..8 {
            serial_numbers[i] = read_le_u32(data, 144 + i * 4);
        }
        Ok(Self {
            major_version: read_le_u32(data, 0),
            minor_version: read_le_u32(data, 4),
            software_id: read_le_u32(data, 136),
            soc_hw_vers,
            jtag_id: read_le_u64(data, 264),
            serial_numbers,
            oem_id: read_le_u32(data, 304),
            oem_product_id: read_le_u32(data, 308),
            anti_rollback_version: read_le_u32(data, 312),
            mrc_index: read_le_u32(data, 316),
            debug: read_le_u32(data, 320),
            secondary_software_id: read_le_u32(data, 324),
            flags: read_le_u32(data, 328),
        })
    }

    pub fn get_arb_version(&self) -> u32 {
        self.anti_rollback_version
    }
}

#[derive(Debug, Clone)]
pub struct MetadataV10 {
    pub base: MetadataV00,
    pub in_use_jtag_id: u32,
    pub oem_product_id_independent: u32,
}

impl MetadataV10 {
    pub const SIZE: usize = 336;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = MetadataV00::from_bytes(data)?;
        if data.len() < Self::SIZE {
            return Err("Insufficient data for MetadataV10");
        }
        Ok(Self {
            base,
            in_use_jtag_id: read_le_u32(data, 332),
            oem_product_id_independent: read_le_u32(data, 336),
        })
    }

    pub fn get_arb_version(&self) -> u32 {
        self.base.anti_rollback_version
    }
}

#[derive(Debug, Clone)]
pub struct MetadataV20 {
    pub major_version: u32,
    pub minor_version: u32,
    pub anti_rollback_version: u32,
    pub mrc_index: u32,
    pub soc_hw_vers: [u32; 32],
    pub soc_feature_id: u32,
    pub jtag_id: u64,
    pub serial_numbers: [u32; 8],
    pub oem_id: u32,
    pub oem_product_id: u32,
    pub soc_lifecycle_state: u32,
    pub oem_lifecycle_state: u32,
    pub oem_root_certificate_hash_algorithm: u32,
    pub oem_root_certificate_hash: [u8; 64],
    pub flags: u32,
}

impl MetadataV20 {
    pub const SIZE: usize = 456;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 {
            return Err("Insufficient data for MetadataV20");
        }
        let mut soc_hw_vers = [0u32; 32];
        let mut serial_numbers = [0u32; 8];
        let mut oem_root_certificate_hash = [0u8; 64];
        for i in 0..32 {
            if 16 + i * 4 + 4 <= data.len() {
                soc_hw_vers[i] = read_le_u32(data, 16 + i * 4);
            }
        }
        for i in 0..8 {
            if 152 + i * 4 + 4 <= data.len() {
                serial_numbers[i] = read_le_u32(data, 152 + i * 4);
            }
        }
        if data.len() >= 304 {
            let copy_len = 64.min(data.len() - 240);
            oem_root_certificate_hash[..copy_len].copy_from_slice(&data[240..240 + copy_len]);
        }
        Ok(Self {
            major_version: read_le_u32(data, 0),
            minor_version: read_le_u32(data, 4),
            anti_rollback_version: read_le_u32(data, 8),
            mrc_index: read_le_u32(data, 12),
            soc_hw_vers,
            soc_feature_id: if data.len() > 236 { read_le_u32(data, 232) } else { 0 },
            jtag_id: if data.len() > 244 { read_le_u64(data, 236) } else { 0 },
            serial_numbers,
            oem_id: if data.len() > 228 { read_le_u32(data, 224) } else { 0 },
            oem_product_id: if data.len() > 232 { read_le_u32(data, 228) } else { 0 },
            soc_lifecycle_state: if data.len() > 320 { read_le_u32(data, 316) } else { 0 },
            oem_lifecycle_state: if data.len() > 324 { read_le_u32(data, 320) } else { 0 },
            oem_root_certificate_hash_algorithm: if data.len() > 328 { read_le_u32(data, 324) } else { 0 },
            oem_root_certificate_hash,
            flags: if data.len() > 332 { read_le_u32(data, 328) } else { 0 },
        })
    }

    pub fn get_arb_version(&self) -> u32 {
        self.anti_rollback_version
    }
}

#[derive(Debug, Clone)]
pub struct MetadataV30 {
    pub base: MetadataV20,
    pub qti_lifecycle_state: u32,
}

impl MetadataV30 {
    pub const SIZE: usize = 460;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = MetadataV20::from_bytes(data)?;
        if data.len() < Self::SIZE {
            return Err("Insufficient data for MetadataV30");
        }
        Ok(Self {
            base,
            qti_lifecycle_state: read_le_u32(data, 456),
        })
    }

    pub fn get_arb_version(&self) -> u32 {
        self.base.anti_rollback_version
    }
}

#[derive(Debug, Clone)]
pub struct MetadataV31 {
    pub base: MetadataV30,
    pub measurement_register_target: u32,
}

impl MetadataV31 {
    pub const SIZE: usize = 464;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = MetadataV30::from_bytes(data)?;
        if data.len() < Self::SIZE {
            return Err("Insufficient data for MetadataV31");
        }
        Ok(Self {
            base,
            measurement_register_target: read_le_u32(data, 460),
        })
    }

    pub fn get_arb_version(&self) -> u32 {
        self.base.base.anti_rollback_version
    }
}

#[derive(Debug, Clone)]
pub struct CommonMetadataV00 {
    pub major_version: u32,
    pub minor_version: u32,
    pub one_shot_hash_algorithm: u32,
    pub segment_hash_algorithm: u32,
}

impl CommonMetadataV00 {
    pub const SIZE: usize = 16;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::SIZE {
            return Err("Insufficient data for CommonMetadataV00");
        }
        Ok(Self {
            major_version: read_le_u32(data, 0),
            minor_version: read_le_u32(data, 4),
            one_shot_hash_algorithm: read_le_u32(data, 8),
            segment_hash_algorithm: read_le_u32(data, 12),
        })
    }
}

#[derive(Debug, Clone)]
pub struct CommonMetadataV01 {
    pub base: CommonMetadataV00,
    pub zi_segment_hash_algorithm: u32,
}

impl CommonMetadataV01 {
    pub const SIZE: usize = 20;

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = CommonMetadataV00::from_bytes(data)?;
        if data.len() < Self::SIZE {
            return Err("Insufficient data for CommonMetadataV01");
        }
        Ok(Self {
            base,
            zi_segment_hash_algorithm: read_le_u32(data, 16),
        })
    }
}

#[derive(Debug)]
pub enum Metadata {
    V00(MetadataV00),
    V10(MetadataV10),
    V20(MetadataV20),
    V30(MetadataV30),
    V31(MetadataV31),
}

impl Metadata {
    pub fn from_bytes(data: &[u8], major: u32, minor: u32) -> Result<Self, &'static str> {
        match (major, minor) {
            (0, 0) => Ok(Metadata::V00(MetadataV00::from_bytes(data)?)),
            (1, 0) => Ok(Metadata::V10(MetadataV10::from_bytes(data)?)),
            (2, 0) => Ok(Metadata::V20(MetadataV20::from_bytes(data)?)),
            (3, 0) => Ok(Metadata::V30(MetadataV30::from_bytes(data)?)),
            (3, 1) => Ok(Metadata::V31(MetadataV31::from_bytes(data)?)),
            _ => {
                if data.len() >= 12 {
                    let arb = read_le_u32(data, 8);
                    if arb <= 127 {
                        return Ok(Metadata::V20(MetadataV20 {
                            major_version: major,
                            minor_version: minor,
                            anti_rollback_version: arb,
                            mrc_index: if data.len() > 16 { read_le_u32(data, 12) } else { 0 },
                            soc_hw_vers: [0; 32],
                            soc_feature_id: 0,
                            jtag_id: 0,
                            serial_numbers: [0; 8],
                            oem_id: 0,
                            oem_product_id: 0,
                            soc_lifecycle_state: 0,
                            oem_lifecycle_state: 0,
                            oem_root_certificate_hash_algorithm: 0,
                            oem_root_certificate_hash: [0; 64],
                            flags: 0,
                        }));
                    }
                }
                Err("Unknown metadata version")
            }
        }
    }

    pub fn get_arb_version(&self) -> u32 {
        match self {
            Metadata::V00(m) => m.get_arb_version(),
            Metadata::V10(m) => m.get_arb_version(),
            Metadata::V20(m) => m.get_arb_version(),
            Metadata::V30(m) => m.get_arb_version(),
            Metadata::V31(m) => m.get_arb_version(),
        }
    }

    pub fn get_version_string(&self) -> String {
        match self {
            Metadata::V00(m) => format!("{}.{}", m.major_version, m.minor_version),
            Metadata::V10(m) => format!("{}.{}", m.base.major_version, m.base.minor_version),
            Metadata::V20(m) => format!("{}.{}", m.major_version, m.minor_version),
            Metadata::V30(m) => format!("{}.{}", m.base.major_version, m.base.minor_version),
            Metadata::V31(m) => format!("{}.{}", m.base.base.major_version, m.base.base.minor_version),
        }
    }
}

#[derive(Debug)]
pub enum CommonMetadata {
    V00(CommonMetadataV00),
    V01(CommonMetadataV01),
}

impl CommonMetadata {
    pub fn from_bytes(data: &[u8], major: u32, minor: u32) -> Result<Self, &'static str> {
        match (major, minor) {
            (0, 0) => Ok(CommonMetadata::V00(CommonMetadataV00::from_bytes(data)?)),
            (0, 1) => Ok(CommonMetadata::V01(CommonMetadataV01::from_bytes(data)?)),
            _ => Err("Unknown common metadata version"),
        }
    }

    pub fn get_version_string(&self) -> String {
        match self {
            CommonMetadata::V00(m) => format!("{}.{}", m.major_version, m.minor_version),
            CommonMetadata::V01(m) => format!("{}.{}", m.base.major_version, m.base.minor_version),
        }
    }
}
