pub mod fuse_check;

use crate::config::profile::{ImageFormat, SecurityProfile};
use crate::hash_segment::defines::{is_valid_hash_segment_version, ARB_VALUE_MAX};
use crate::elf::parser::ElfParser;
use crate::error::{Error, Result};
use crate::hash_segment::defines as hs_defs;

use crate::hash_segment::parser::HashSegmentInfo;

pub fn validate_image(image_data: &[u8], profile: &SecurityProfile) -> Result<()> {
    #[cfg(not(feature = "validate"))]
    {
        let _ = (image_data, profile);
        return Err(Error::Custom(
            "Image validation not supported in this build".into(),
        ));
    }

    #[cfg(feature = "validate")]
    {
        let parser = ElfParser::from_bytes(image_data)
            .map_err(|e| Error::ElfParse(format!("failed to parse ELF header: {}", e)))?;

        let mut issues = Vec::new();

        match profile.image_format {
            ImageFormat::Mbn => {
                issues.push(format!(
                    "Profile expects MBN format but image is ELF (profile.image_format={:?})",
                    profile.image_format
                ));
                return Err(Error::Custom(format!(
                    "Image validation found {} issue(s):\n  - {}",
                    issues.len(),
                    issues.join("\n  - ")
                )));
            }
            ImageFormat::Elf => {
                if parser.find_hash_segment().is_some() {
                    issues.push(
                        "Profile expects plain ELF (no hash segment) but image contains a HASH segment"
                            .into(),
                    );
                }
            }
            ImageFormat::ElfWithHash => {
                if parser.find_hash_segment().is_none() {
                    issues.push(
                        "Profile expects ELF with hash segment but no HASH segment found in image"
                            .into(),
                    );
                }
            }
        }

        if let Some(hash_phdr) = parser.find_hash_segment() {
            let offset = hash_phdr.p_offset as usize;
            match HashSegmentInfo::parse(image_data, offset) {
                Ok(Some(info)) => {
                    let hdr_version = info.header.version();
                    if !is_valid_hash_segment_version(hdr_version) {
                        issues.push(format!(
                            "Hash segment version {} is not supported (supported: 3, 5, 6, 7, 8)",
                            hdr_version
                        ));
                    }

                    if let Some(ref om) = info.oem_metadata {
                        let arb = om.get_arb_version();
                        if arb > ARB_VALUE_MAX {
                            issues.push(format!(
                                "ARB value {} exceeds expected max {}",
                                arb, ARB_VALUE_MAX
                            ));
                        }
                    } else {
                        issues.push("No OEM metadata found in hash segment".into());
                    }

                    if let Some(ref enc) = info.encryption {
                        issues.push(format!(
                            "Image is encrypted ({}) - cannot fully validate content",
                            enc.scheme_name()
                        ));
                    }

                    if info.hashes.is_empty() {
                        issues.push("Hash table is empty (size=0)".into());
                    }
                }
                Ok(None) => {
                    issues.push("Hash segment header failed plausibility check".into());
                }
                Err(e) => {
                    issues.push(format!("Hash segment parse error: {}", e));
                }
            }
        } else if !matches!(profile.image_format, ImageFormat::Elf) {
            issues.push("No HASH segment found in image".into());
        }

        if profile.hash_algorithm.digest_size() != hs_defs::SHA256_SIZE {
            issues.push(format!(
                "Profile specifies non-standard hash algorithm (size={})",
                profile.hash_algorithm.digest_size()
            ));
        }

        if issues.is_empty() {
            Ok(())
        } else {
            Err(Error::Custom(format!(
                "Image validation found {} issue(s):\n  - {}",
                issues.len(),
                issues.join("\n  - ")
            )))
        }
    }
}
