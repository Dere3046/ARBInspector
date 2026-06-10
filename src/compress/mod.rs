#[cfg(feature = "compress")]
pub mod lzma {
    use crate::error::{Error, Result};

    pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
        use lzma_rs::lzma_compress;
        let mut compressed = Vec::new();
        lzma_compress(&mut std::io::Cursor::new(data), &mut compressed)
            .map_err(|e| Error::Custom(format!("LZMA compress failed: {}", e)))?;
        Ok(compressed)
    }

    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        use lzma_rs::lzma_decompress;
        let mut decompressed = Vec::new();
        lzma_decompress(&mut std::io::Cursor::new(data), &mut decompressed)
            .map_err(|e| Error::Custom(format!("LZMA decompress failed: {}", e)))?;
        Ok(decompressed)
    }

    pub fn compress_xz(data: &[u8]) -> Result<Vec<u8>> {
        use lzma_rs::xz_compress;
        let mut compressed = Vec::new();
        xz_compress(&mut std::io::Cursor::new(data), &mut compressed)
            .map_err(|e| Error::Custom(format!("XZ compress failed: {}", e)))?;
        Ok(compressed)
    }

    pub fn decompress_xz(data: &[u8]) -> Result<Vec<u8>> {
        use lzma_rs::xz_decompress;
        let mut decompressed = Vec::new();
        xz_decompress(&mut std::io::Cursor::new(data), &mut decompressed)
            .map_err(|e| Error::Custom(format!("XZ decompress failed: {}", e)))?;
        Ok(decompressed)
    }
}

#[cfg(not(feature = "compress"))]
pub mod lzma {
    use crate::error::{Error, Result};

    pub fn compress(_data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Custom("LZMA compression not supported in this build".into()))
    }

    pub fn decompress(_data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Custom("LZMA decompression not supported in this build".into()))
    }

    pub fn compress_xz(_data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Custom("XZ compression not supported in this build".into()))
    }

    pub fn decompress_xz(_data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Custom("XZ decompression not supported in this build".into()))
    }
}

pub mod pil {
    use crate::elf::header::ElfHeader;
    use crate::elf::parser::ElfParser;
    use crate::elf::program_header::ProgramHeader;
    use crate::error::{Error, Result};
    use std::path::Path;

    pub struct PilSplitOutput {
        pub mdt: Vec<u8>,
        pub segments: Vec<Vec<u8>>,
    }

    pub fn split(elf_data: &[u8]) -> Result<PilSplitOutput> {
        let parser = ElfParser::from_bytes(elf_data)
            .map_err(|e| Error::ElfParse(e.to_string()))?;

        if parser.program_headers.len() > 100 {
            return Err(Error::Custom(format!(
                "Cannot PIL split: {} segments exceeds max of 100",
                parser.program_headers.len()
            )));
        }

        let mut mdt = Vec::new();
        mdt.extend_from_slice(&elf_data[..52.min(elf_data.len())]);

        let phdr_size = parser.header.e_phentsize as usize;
        let phdr_start = parser.header.e_phoff as usize;
        for i in 0..parser.program_headers.len() {
            let phdr_offset = phdr_start + i * phdr_size;
            let end = phdr_offset + phdr_size;
            if end <= elf_data.len() {
                mdt.extend_from_slice(&elf_data[phdr_offset..end]);
            }
        }

        let segments: Vec<Vec<u8>> = parser
            .program_headers
            .iter()
            .map(|phdr| {
                if phdr.p_filesz == 0 {
                    Vec::new()
                } else {
                    let start = phdr.p_offset as usize;
                    let end = start + phdr.p_filesz as usize;
                    if end <= elf_data.len() {
                        elf_data[start..end].to_vec()
                    } else {
                        Vec::new()
                    }
                }
            })
            .collect();

        Ok(PilSplitOutput { mdt, segments })
    }

    pub fn write_to_directory(
        elf_data: &[u8],
        stem: &str,
        dir: &Path,
    ) -> Result<Vec<std::path::PathBuf>> {
        let out = split(elf_data)?;
        let mut written = Vec::new();

        let mdt_path = dir.join(format!("{}.mdt", stem));
        std::fs::write(&mdt_path, &out.mdt)
            .map_err(|e| Error::Io(e))?;
        written.push(mdt_path);

        for (i, seg) in out.segments.iter().enumerate() {
            let b_path = dir.join(format!("{}.b{:02}", stem, i));
            std::fs::write(&b_path, seg)
                .map_err(|e| Error::Io(e))?;
            written.push(b_path);
        }

        Ok(written)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn sample_elf32() -> Vec<u8> {
            let seg_data = b"HELLO_XBL_2026!";
            let phdr_count: u16 = 1;
            let ehdr_size: u16 = 52;
            let phdr_size: u16 = 32;
            let phoff: u32 = ehdr_size as u32;
            let data_off: u32 = phoff + phdr_count as u32 * phdr_size as u32;
            let filesz: u32 = seg_data.len() as u32;

            let mut d = Vec::new();
            d.extend_from_slice(b"\x7fELF");
            d.push(1); d.push(1); d.push(1); d.push(0);
            d.extend_from_slice(&[0u8; 8]);
            d.extend_from_slice(&2u16.to_le_bytes());
            d.extend_from_slice(&40u16.to_le_bytes());
            d.extend_from_slice(&1u32.to_le_bytes());
            d.extend_from_slice(&0u32.to_le_bytes());
            d.extend_from_slice(&phoff.to_le_bytes());
            d.extend_from_slice(&0u32.to_le_bytes());
            d.extend_from_slice(&0u32.to_le_bytes());
            d.extend_from_slice(&ehdr_size.to_le_bytes());
            d.extend_from_slice(&phdr_size.to_le_bytes());
            d.extend_from_slice(&phdr_count.to_le_bytes());
            d.extend_from_slice(&0u16.to_le_bytes());
            d.extend_from_slice(&0u16.to_le_bytes());
            d.extend_from_slice(&0u16.to_le_bytes());
            d.extend_from_slice(&1u32.to_le_bytes());
            d.extend_from_slice(&data_off.to_le_bytes());
            d.extend_from_slice(&0u32.to_le_bytes());
            d.extend_from_slice(&0u32.to_le_bytes());
            d.extend_from_slice(&filesz.to_le_bytes());
            d.extend_from_slice(&filesz.to_le_bytes());
            d.extend_from_slice(&7u32.to_le_bytes());
            d.extend_from_slice(&4u32.to_le_bytes());
            d.extend_from_slice(seg_data);
            d
        }

        #[test]
        fn test_pil_split_basic() {
            let elf = sample_elf32();
            let parser = crate::elf::parser::ElfParser::from_bytes(&elf).unwrap();
            let ph = &parser.program_headers[0];
            let result = split(&elf).unwrap();
            assert_eq!(result.segments.len(), 1);
            assert_eq!(result.segments[0], b"HELLO_XBL_2026!");
        }

        #[test]
        fn test_pil_split_mdt_contains_header() {
            let elf = sample_elf32();
            let result = split(&elf).unwrap();
            assert!(result.mdt.len() >= 52);
        }

    }
}

#[cfg(test)]
#[cfg(feature = "compress")]
mod tests_lzma {
    use crate::compress::lzma;

    #[test]
    fn test_lzma_compress_decompress() {
        let data = b"test data for lzma roundtrip! ".repeat(10);
        let compressed = lzma::compress(&data).unwrap();
        assert!(compressed.len() < data.len());
        let decompressed = lzma::decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_xz_compress_decompress() {
        let data = b"test data for xz roundtrip! ".repeat(10);
        let compressed = lzma::compress_xz(&data).unwrap();
        let decompressed = lzma::decompress_xz(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
