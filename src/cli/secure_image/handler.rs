use crate::cli::args::SecureImageArgs;
use crate::config::device_restrictions::DeviceRestrictions;
use crate::config::profile::{
    Authority, EncryptConfig, EncryptionMode, EncryptionOrder, EncryptionType, HashAlgorithm,
    SecurityProfile, SignConfig, SigningMode,
};
use crate::core::encryption_order::Operation;
use crate::core::pipeline::Pipeline;
use crate::error::{Error, Result};

pub fn handle_secure_image(args: SecureImageArgs) -> Result<()> {
    let data = match &args.infile {
        Some(path) => std::fs::read(path).map_err(Error::Io)?,
        None => return Err(Error::InvalidArgument("--infile is required".into())),
    };

    let profile = build_profile(&args)?;
    let restrictions = build_restrictions(&args);

    let mut ops = Vec::new();
    if args.do_hash {
        ops.push(Operation::Hash);
    }
    if args.do_sign {
        ops.push(Operation::Sign);
    }
    if args.do_encrypt {
        ops.push(Operation::Encrypt);
    }

    if ops.is_empty() && !args.do_inspect {
        return Err(Error::InvalidArgument(
            "No operation specified. Use --hash, --sign, --encrypt, or --inspect".into(),
        ));
    }

    if args.do_inspect {
        return inspect_image(&data, &profile);
    }

    let mut pipeline = Pipeline::new(&profile, &data, Some(&restrictions));
    pipeline.set_operations(&ops);

    let output = pipeline.run()?;

    if let Some(outpath) = &args.outfile {
        std::fs::write(outpath, &output).map_err(Error::Io)?;
    }

    Ok(())
}

fn inspect_image(data: &[u8], _profile: &SecurityProfile) -> Result<()> {
    use crate::elf::defines::{self as elf_defs, p_flags_os_access_type, p_flags_os_page_mode, p_flags_os_segment_type, perm_to_string, p_type_to_string, os_segment_type_to_string, os_access_type_to_string, os_page_mode_to_string};
    use crate::elf::header::ElfHeader;
    use crate::elf::parser::ElfParser;
    use crate::hash_segment::defines::ARB_VALUE_MAX;
    use crate::hash_segment::metadata::{CommonMetadata, Metadata};
    use crate::hash_segment::parser::HashSegmentInfo;
    use crate::hash_segment::parser::SignatureStatus;

    if data.len() < 52 || &data[..4] != b"\x7fELF" {
        return Err(Error::Custom("Not a valid ELF file".into()));
    }

    let elf_header = ElfHeader::from_bytes(data)
        .map_err(|e| Error::ElfParse(e.to_string()))?;
    let parser = ElfParser::from_bytes(data)
        .map_err(|e| Error::ElfParse(e.to_string()))?;

    println!("ELF Header:");
    println!("  Class: {}", if elf_header.is_32bit() { "ELF32" } else { "ELF64" });
    println!("  Entry: 0x{:x}", elf_header.e_entry);
    println!("  Machine: 0x{:x}", elf_header.e_machine);
    println!("  Program headers: {}", elf_header.e_phnum);
    println!();

    if let Some(hash_phdr) = parser.find_hash_segment() {
        let offset = hash_phdr.p_offset as usize;
        if let Ok(Some(info)) = HashSegmentInfo::parse(data, offset) {
            let hdr = &info.header;
            println!("Hash Table Segment Header:");
            println!("  Version: {}", hdr.version());
            println!("  Common Metadata Size: {} (bytes)", hdr.common_metadata_size());
            println!("  OEM Metadata Size: {} (bytes)", hdr.oem_metadata_size());
            println!("  Hash Table Size: {} (bytes)", hdr.hash_table_size());
            println!();

            match info.signature_status() {
                SignatureStatus::Both => println!("Signed: Yes (QTI + OEM)"),
                SignatureStatus::QtiOnly => println!("Signed: Yes (QTI only)"),
                SignatureStatus::OemOnly => println!("Signed: Yes (OEM only)"),
                SignatureStatus::Unsigned => println!("Signed: No"),
            }
            println!();

            if let Some(ref om) = info.oem_metadata {
                println!("OEM Metadata:");
                println!("  Version: {}", om.get_version_string());
                println!("  Anti-Rollback Version: {}", om.get_arb_version());
                println!();
            }

            if let Some(arb) = info.get_arb_version() {
                if arb <= ARB_VALUE_MAX {
                    println!("Anti-Rollback Version: {}", arb);
                }
            }
        } else {
            println!("Hash segment found but could not be fully parsed.");
        }
    } else {
        println!("No HASH segment found.");
    }

    Ok(())
}

fn build_profile(args: &SecureImageArgs) -> Result<SecurityProfile> {
    let authority = if args.qti {
        Authority::Qti
    } else {
        Authority::Oem
    };

    let hash_algo = match args.segment_hash_algorithm {
        Some(1) => HashAlgorithm::Sha384,
        Some(2) => HashAlgorithm::Sha512,
        _ => HashAlgorithm::Sha256,
    };

    let sign = if args.do_sign {
        let mode = match args.signing_mode.as_deref() {
            Some("test") => SigningMode::Test,
            _ => SigningMode::Local,
        };
        #[cfg(not(feature = "sign"))]
        {
            return Err(Error::Custom(
                "This build does not support signing. Rebuild with 'sign' feature".into(),
            ));
        }
        #[cfg(feature = "sign")]
        {
            Some(SignConfig {
                mode,
                signature_format: args.signature_format.clone().unwrap_or_else(|| "ecdsa-p384".into()),
                cert_chain_depth: 2,
                root_cert_count: 1,
                pad_for_hybrid_sign: false,
            })
        }
    } else {
        None
    };

    let encrypt = if args.do_encrypt {
        #[cfg(not(feature = "encrypt"))]
        {
            return Err(Error::Custom(
                "This build does not support encryption. Rebuild with 'encrypt' feature".into(),
            ));
        }
        #[cfg(feature = "encrypt")]
        {
            let etype = match args.encryption_format.as_deref() {
                Some("uie") => EncryptionType::Uie,
                _ => EncryptionType::Qbec,
            };
            let mode = match args.encryption_mode.as_deref() {
                Some("test") => EncryptionMode::Test,
                _ => EncryptionMode::Local,
            };
            Some(EncryptConfig {
                mode,
                etype,
                order: EncryptionOrder::EncryptThenSign,
            })
        }
    } else {
        None
    };

    Ok(SecurityProfile {
        authority,
        image_format: crate::config::profile::ImageFormat::ElfWithHash,
        hash_algorithm: hash_algo,
        sign,
        encrypt,
    })
}

pub fn parse_secure_image_args(args: &[String]) -> Result<SecureImageArgs> {
    let mut out = SecureImageArgs::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "secure-image" => { i += 1; }
            "--infile" => {
                i += 1;
                out.infile = Some(std::path::PathBuf::from(&args[i]));
                i += 1;
            }
            "--outfile" => {
                i += 1;
                out.outfile = Some(std::path::PathBuf::from(&args[i]));
                i += 1;
            }
            "--image-id" => {
                i += 1;
                out.image_id = Some(u32::from_str_radix(args[i].trim_start_matches("0x"), 16).map_err(|_| {
                    Error::InvalidArgument("invalid --image-id".into())
                })?);
                i += 1;
            }
            "--qti" => { out.qti = true; i += 1; }
            "--hash" => { out.do_hash = true; i += 1; }
            "--sign" => { out.do_sign = true; i += 1; }
            "--encrypt" => { out.do_encrypt = true; i += 1; }
            "--inspect" => { out.do_inspect = true; i += 1; }
            "--validate" => { out.do_validate = true; i += 1; }
            "--compress" => { out.do_compress = true; i += 1; }
            "--segment-hash-algorithm" => {
                i += 1;
                out.segment_hash_algorithm = Some(args[i].parse().map_err(|_| {
                    Error::InvalidArgument("invalid hash algorithm".into())
                })?);
                i += 1;
            }
            "--anti-rollback-version" | "-a" => {
                i += 1;
                out.anti_rollback = Some(args[i].parse().map_err(|_| {
                    Error::InvalidArgument("invalid ARB value".into())
                })?);
                i += 1;
            }
            "--oem-id" => {
                i += 1;
                out.oem_id = Some(u32::from_str_radix(args[i].trim_start_matches("0x"), 16).map_err(|_| {
                    Error::InvalidArgument("invalid --oem-id".into())
                })?);
                i += 1;
            }
            "--oem-product-id" => {
                i += 1;
                out.oem_product_id = Some(u32::from_str_radix(args[i].trim_start_matches("0x"), 16).map_err(|_| {
                    Error::InvalidArgument("invalid --oem-product-id".into())
                })?);
                i += 1;
            }
            "--serial-number" => {
                i += 1;
                out.serial_number = Some(args[i].parse().map_err(|_| {
                    Error::InvalidArgument("invalid serial number".into())
                })?);
                i += 1;
            }
            "--signing-mode" => {
                i += 1;
                out.signing_mode = Some(args[i].clone());
                i += 1;
            }
            "--signature-format" => {
                i += 1;
                out.signature_format = Some(args[i].clone());
                i += 1;
            }
            "--root-certificate" => {
                i += 1;
                out.root_certificate = Some(std::path::PathBuf::from(&args[i]));
                i += 1;
            }
            "--ca-certificate" => {
                i += 1;
                out.ca_certificate = Some(std::path::PathBuf::from(&args[i]));
                i += 1;
            }
            "--root-key" => {
                i += 1;
                out.root_key = Some(std::path::PathBuf::from(&args[i]));
                i += 1;
            }
            "--ca-key" => {
                i += 1;
                out.ca_key = Some(std::path::PathBuf::from(&args[i]));
                i += 1;
            }
            "--encryption-mode" => {
                i += 1;
                out.encryption_mode = Some(args[i].clone());
                i += 1;
            }
            "--encryption-format" => {
                i += 1;
                out.encryption_format = Some(args[i].clone());
                i += 1;
            }
            "--help" | "-h" => {
                crate::cli::secure_image::cmdline_dict::print_help();
                std::process::exit(0);
            }
            _ => {
                return Err(Error::InvalidArgument(format!("Unknown argument: {}", args[i])));
            }
        }
    }
    Ok(out)
}

fn build_restrictions(args: &SecureImageArgs) -> DeviceRestrictions {
    DeviceRestrictions {
        oem_id: args.oem_id,
        oem_product_id: args.oem_product_id,
        anti_rollback_version: args.anti_rollback,
        serial_number: args.serial_number,
        ..DeviceRestrictions::default()
    }
}
