#![allow(dead_code)]

#[inline]
fn read_le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off+4].try_into().unwrap())
}

pub const MBN_HDR_SIZE: usize = 40;
pub const MBN_V7_HDR_SIZE: usize = 64;
pub const MBN_V8_HDR_SIZE: usize = 80;

#[derive(Debug, Clone)]
pub struct MbnHeader {
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

impl MbnHeader {
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < MBN_HDR_SIZE {
            return Err("Insufficient data for MBN header");
        }
        Ok(Self {
            image_id: read_le_u32(data, 0),
            version: read_le_u32(data, 4),
            image_src: read_le_u32(data, 8),
            image_dest_ptr: read_le_u32(data, 12),
            image_size: read_le_u32(data, 16),
            code_size: read_le_u32(data, 20),
            sig_ptr: read_le_u32(data, 24),
            sig_size: read_le_u32(data, 28),
            cert_chain_ptr: read_le_u32(data, 32),
            cert_chain_size: read_le_u32(data, 36),
        })
    }

    pub fn header_size(&self) -> usize {
        match self.version {
            7 => MBN_V7_HDR_SIZE,
            8 => MBN_V8_HDR_SIZE,
            _ => MBN_HDR_SIZE,
        }
    }
}

#[derive(Debug)]
pub struct Mbn {
    pub header: MbnHeader,
    pub code: Vec<u8>,
}

impl Mbn {
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("Insufficient data for MBN");
        }
        let header = MbnHeader::from_bytes(data)?;
        let header_size = header.header_size();
        if data.len() < header_size {
            return Err("Insufficient data for MBN with padding");
        }
        let code = data[header_size..].to_vec();
        Ok(Self { header, code })
    }
}