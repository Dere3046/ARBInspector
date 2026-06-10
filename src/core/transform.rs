use crate::config::profile::ImageFormat;
use crate::error::{Error, Result};

pub fn check_format_supported(data: &[u8], target: ImageFormat) -> Result<()> {
    match target {
        ImageFormat::ElfWithHash => {
            if data.len() < 4 || &data[..4] != b"\x7fELF" {
                return Err(Error::InvalidArgument(
                    "Input must be an ELF file for ELF-with-hash format".into(),
                ));
            }
            Ok(())
        }
        ImageFormat::Mbn => {
            Ok(())
        }
        ImageFormat::Elf => {
            if data.len() < 4 || &data[..4] != b"\x7fELF" {
                return Err(Error::InvalidArgument(
                    "Input must be an ELF file".into(),
                ));
            }
            Ok(())
        }
    }
}
