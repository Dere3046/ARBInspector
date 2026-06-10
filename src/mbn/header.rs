#![allow(dead_code)]

use crate::data::read_le_u32;
use crate::mbn::defines::{
    header_size_for_version, is_valid_version, CERT_CHAIN_PTR_OFFSET, CERT_CHAIN_SIZE_OFFSET,
    CODE_SIZE_OFFSET, IMAGE_DEST_PTR_OFFSET, IMAGE_ID_OFFSET, IMAGE_SIZE_OFFSET,
    IMAGE_SRC_OFFSET, MBN_V7_CERT2_PTR_OFFSET, MBN_V7_CERT2_SIZE_OFFSET, MBN_V7_HDR_SIZE,
    MBN_V7_RESERVED_OFFSET, MBN_V7_SIG2_PTR_OFFSET, MBN_V7_SIG2_SIZE_OFFSET,
    MBN_V8_HDR_SIZE, MBN_V8_OEM_CERT2_PTR_OFFSET, MBN_V8_OEM_CERT2_SIZE_OFFSET,
    MBN_V8_OEM_CERT_PTR_OFFSET, MBN_V8_OEM_CERT_SIZE_OFFSET, MBN_V8_OEM_SIG2_PTR_OFFSET,
    MBN_V8_OEM_SIG2_SIZE_OFFSET, MBN_V8_OEM_SIG_PTR_OFFSET, MBN_V8_OEM_SIG_SIZE_OFFSET,
    MBN_V8_RESERVED_OFFSET, SIG_PTR_OFFSET, SIG_SIZE_OFFSET, VERSION_OFFSET,
};

#[derive(Debug, Clone)]
pub struct MbnHeaderV3 {
    pub image_id: u32,
    pub version: u32,
    pub image_src: u32,
    pub image_dest_ptr: u32,
    pub image_size: u32,
    pub code_size: u32,
    pub sig_ptr: u32,
    pub sig_size: u32,
    pub cert_chain_ptr: u32,
    pub cert_chain_size: u32,
}

#[derive(Debug, Clone)]
pub struct MbnHeaderV7 {
    pub base: MbnHeaderV3,
    pub sig2_ptr: u32,
    pub sig2_size: u32,
    pub cert2_ptr: u32,
    pub cert2_size: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone)]
pub struct MbnHeaderV8 {
    pub base: MbnHeaderV3,
    pub oem_sig_ptr: u32,
    pub oem_sig_size: u32,
    pub oem_cert_ptr: u32,
    pub oem_cert_size: u32,
    pub oem_sig2_ptr: u32,
    pub oem_sig2_size: u32,
    pub oem_cert2_ptr: u32,
    pub oem_cert2_size: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone)]
pub enum MbnHeader {
    V3(MbnHeaderV3),
    V5(MbnHeaderV3),
    V6(MbnHeaderV3),
    V7(MbnHeaderV7),
    V8(MbnHeaderV8),
}

impl MbnHeader {
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("Insufficient data for MBN header");
        }
        let version = read_le_u32(data, VERSION_OFFSET);
        if !is_valid_version(version) {
            return Err("Unknown MBN version");
        }
        let hdr_size = header_size_for_version(version);
        if data.len() < hdr_size {
            return Err("Insufficient data for MBN header version");
        }

        let base = MbnHeaderV3 {
            image_id: read_le_u32(data, IMAGE_ID_OFFSET),
            version,
            image_src: read_le_u32(data, IMAGE_SRC_OFFSET),
            image_dest_ptr: read_le_u32(data, IMAGE_DEST_PTR_OFFSET),
            image_size: read_le_u32(data, IMAGE_SIZE_OFFSET),
            code_size: read_le_u32(data, CODE_SIZE_OFFSET),
            sig_ptr: read_le_u32(data, SIG_PTR_OFFSET),
            sig_size: read_le_u32(data, SIG_SIZE_OFFSET),
            cert_chain_ptr: read_le_u32(data, CERT_CHAIN_PTR_OFFSET),
            cert_chain_size: read_le_u32(data, CERT_CHAIN_SIZE_OFFSET),
        };

        match version {
            3 | 5 | 6 => Ok(match version {
                3 => MbnHeader::V3(base),
                5 => MbnHeader::V5(base),
                _ => MbnHeader::V6(base),
            }),
            7 => {
                if data.len() < MBN_V7_HDR_SIZE {
                    return Err("Insufficient data for MBNv7 header");
                }
                Ok(MbnHeader::V7(MbnHeaderV7 {
                    base,
                    sig2_ptr: read_le_u32(data, MBN_V7_SIG2_PTR_OFFSET),
                    sig2_size: read_le_u32(data, MBN_V7_SIG2_SIZE_OFFSET),
                    cert2_ptr: read_le_u32(data, MBN_V7_CERT2_PTR_OFFSET),
                    cert2_size: read_le_u32(data, MBN_V7_CERT2_SIZE_OFFSET),
                    reserved: read_le_u32(data, MBN_V7_RESERVED_OFFSET),
                }))
            }
            8 => {
                if data.len() < MBN_V8_HDR_SIZE {
                    return Err("Insufficient data for MBNv8 header");
                }
                Ok(MbnHeader::V8(MbnHeaderV8 {
                    base,
                    oem_sig_ptr: read_le_u32(data, MBN_V8_OEM_SIG_PTR_OFFSET),
                    oem_sig_size: read_le_u32(data, MBN_V8_OEM_SIG_SIZE_OFFSET),
                    oem_cert_ptr: read_le_u32(data, MBN_V8_OEM_CERT_PTR_OFFSET),
                    oem_cert_size: read_le_u32(data, MBN_V8_OEM_CERT_SIZE_OFFSET),
                    oem_sig2_ptr: read_le_u32(data, MBN_V8_OEM_SIG2_PTR_OFFSET),
                    oem_sig2_size: read_le_u32(data, MBN_V8_OEM_SIG2_SIZE_OFFSET),
                    oem_cert2_ptr: read_le_u32(data, MBN_V8_OEM_CERT2_PTR_OFFSET),
                    oem_cert2_size: read_le_u32(data, MBN_V8_OEM_CERT2_SIZE_OFFSET),
                    reserved: read_le_u32(data, MBN_V8_RESERVED_OFFSET),
                }))
            }
            _ => unreachable!(),
        }
    }

    pub fn version(&self) -> u32 {
        match self {
            MbnHeader::V3(h) | MbnHeader::V5(h) | MbnHeader::V6(h) => h.version,
            MbnHeader::V7(h) => h.base.version,
            MbnHeader::V8(h) => h.base.version,
        }
    }

    pub fn image_id(&self) -> u32 {
        match self {
            MbnHeader::V3(h) | MbnHeader::V5(h) | MbnHeader::V6(h) => h.image_id,
            MbnHeader::V7(h) => h.base.image_id,
            MbnHeader::V8(h) => h.base.image_id,
        }
    }

    pub fn code_size(&self) -> u32 {
        match self {
            MbnHeader::V3(h) | MbnHeader::V5(h) | MbnHeader::V6(h) => h.code_size,
            MbnHeader::V7(h) => h.base.code_size,
            MbnHeader::V8(h) => h.base.code_size,
        }
    }

    pub fn image_size(&self) -> u32 {
        match self {
            MbnHeader::V3(h) | MbnHeader::V5(h) | MbnHeader::V6(h) => h.image_size,
            MbnHeader::V7(h) => h.base.image_size,
            MbnHeader::V8(h) => h.base.image_size,
        }
    }

    pub fn header_size(&self) -> usize {
        header_size_for_version(self.version())
    }
}
