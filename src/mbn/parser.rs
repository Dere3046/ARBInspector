use crate::mbn::header::MbnHeader;

#[derive(Debug)]
pub struct MbnParser {
    pub header: MbnHeader,
    pub code: Vec<u8>,
}

impl MbnParser {
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let header = MbnHeader::from_bytes(data)?;
        let hdr_size = header.header_size();
        let code = if data.len() > hdr_size {
            data[hdr_size..].to_vec()
        } else {
            Vec::new()
        };
        Ok(MbnParser { header, code })
    }
}
