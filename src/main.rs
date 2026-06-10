use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use anyhow::Context;

mod data;
mod elf;
mod encrypt;
mod error;
mod hash_segment;
mod mbn;
mod verifier;

mod cli;
mod config;
mod core;
mod cipher;
mod compress;
mod sign;
mod validate;

use cli::args::{GlobalArgs, SecureImageArgs};
use cli::secure_image::cmdline_dict;
use cli::secure_image::handler;
use elf::defines::{
    self as elf_defs, os_access_type_to_string, os_page_mode_to_string, os_segment_type_to_string,
    p_flags_os_access_type, p_flags_os_page_mode, p_flags_os_segment_type, perm_to_string,
    p_type_to_string, ELFDATA2LSB,
};
use elf::header::ElfHeader;
use elf::parser::ElfParser;
use elf::program_header::ProgramHeader;
use hash_segment::defines::{self as hs_defs, ARB_VALUE_MAX};
use hash_segment::encryption::qbec;
use hash_segment::metadata::{CommonMetadata, Metadata};
use hash_segment::parser::HashSegmentInfo;
use crate::error::Error;
use verifier::HashVerifier;

const VERSION: &str = env!("CARGO_PKG_VERSION");

enum FileType {
    Elf,
    Mbn,
    Unknown,
}

fn detect_file_type(data: &[u8]) -> FileType {
    if data.starts_with(&elf_defs::ELFMAG) {
        FileType::Elf
    } else if data.len() >= 8 {
        let version = data::read_le_u32(data, 4);
        if hs_defs::is_valid_hash_segment_version(version) {
            FileType::Mbn
        } else {
            FileType::Unknown
        }
    } else {
        FileType::Unknown
    }
}

fn print_phdr_debug(phdrs: &[ProgramHeader], _elf_class: u8) {
    for (i, ph) in phdrs.iter().enumerate() {
        let flags = ph.p_flags;
        let perm = elf_defs::get_perm_value(flags);
        let os_seg = p_flags_os_segment_type(flags);
        let os_access = p_flags_os_access_type(flags);
        let os_page = p_flags_os_page_mode(flags);
        eprintln!(
            "[DEBUG] PH[{}]: type={:#x} offset=0x{:x} filesz=0x{:x} flags={:#x}",
            i, ph.p_type, ph.p_offset, ph.p_filesz, flags
        );
        eprintln!(
            "[DEBUG]        Perm: {} OS_Seg: {} OS_Access: {} Page: {}",
            perm_to_string(perm),
            os_segment_type_to_string(os_seg),
            os_access_type_to_string(os_access),
            os_page_mode_to_string(os_page),
        );
    }
}

fn print_full_output(
    path: &str,
    _elf_data: &[u8],
    elf_header: &ElfHeader,
    phdrs: &[ProgramHeader],
    hash_info: Option<&HashSegmentInfo>,
    arb: Option<u32>,
    elf_class: u8,
) {
    println!("File: {}", path);
    println!(
        "Format: ELF ({})",
        if elf_class == elf_defs::ELFCLASS32 {
            "32-bit"
        } else {
            "64-bit"
        }
    );
    println!("Entry point: 0x{:x}", elf_header.e_entry);
    println!("Machine: 0x{:x}", elf_header.e_machine);
    println!("Type: 0x{:x}", elf_header.e_type);
    println!("Flags: 0x{:x}", elf_header.e_flags);
    println!("Program headers: {}", elf_header.e_phnum);
    println!();

    println!("Program Headers:");
    for (i, phdr) in phdrs.iter().enumerate() {
        let flags = phdr.p_flags;
        let perm = elf_defs::get_perm_value(flags);
        let os_seg_type = p_flags_os_segment_type(flags);
        let os_access = p_flags_os_access_type(flags);
        let os_page_mode = p_flags_os_page_mode(flags);

        println!(
            "  [{}] Type: {} Offset: 0x{:x} VAddr: 0x{:x} FileSize: 0x{:x} MemSize: 0x{:x}",
            i,
            p_type_to_string(phdr.p_type),
            phdr.p_offset,
            phdr.p_vaddr,
            phdr.p_filesz,
            phdr.p_memsz
        );
        println!(
            "      Flags: {:#x} Perm: {} OS_Type: {} OS_Access: {} Page_Mode: {}",
            flags,
            perm_to_string(perm),
            os_segment_type_to_string(os_seg_type),
            os_access_type_to_string(os_access),
            os_page_mode_to_string(os_page_mode),
        );
    }
    println!();

    if let Some(ht) = hash_info {
        let hdr = &ht.header;
        println!("Hash Table Segment Header:");
        println!("  Version: {}", hdr.version());
        println!("  Common Metadata Size: {} (bytes)", hdr.common_metadata_size());
        println!("  QTI Metadata Size: {} (bytes)", hdr.qti_metadata_size());
        println!("  OEM Metadata Size: {} (bytes)", hdr.oem_metadata_size());
        println!("  Hash Table Size: {} (bytes)", hdr.hash_table_size());
        println!("  QTI Signature Size: {} (bytes)", hdr.qti_signature_size());
        println!(
            "  QTI Cert Chain Size: {} (bytes)",
            hdr.qti_certificate_chain_size()
        );
        println!("  OEM Signature Size: {} (bytes)", hdr.oem_signature_size());
        println!(
            "  OEM Cert Chain Size: {} (bytes)",
            hdr.oem_certificate_chain_size()
        );
        println!();
        let status = ht.signature_status();
        use crate::hash_segment::parser::SignatureStatus;
        match status {
            SignatureStatus::Both => println!("Signed: Yes (QTI + OEM)"),
            SignatureStatus::QtiOnly => println!("Signed: Yes (QTI only)"),
            SignatureStatus::OemOnly => println!("Signed: Yes (OEM only)"),
            SignatureStatus::Unsigned => println!("Signed: No"),
        }
        if ht.is_signed() {
            if ht.is_qti_signed() {
                println!("  QTI signature: {} bytes, certificate chain: {} bytes",
                    hdr.qti_signature_size(), hdr.qti_certificate_chain_size());
            }
            if ht.is_oem_signed() {
                println!("  OEM signature: {} bytes, certificate chain: {} bytes",
                    hdr.oem_signature_size(), hdr.oem_certificate_chain_size());
            }
        }
        println!();

        if let Some(ref cm) = ht.common_metadata {
            println!("Common Metadata:");
            println!("  Version: {}", cm.get_version_string());
            match cm {
                CommonMetadata::V00(m) => {
                    println!("  Software ID: 0x{:x}", m.software_id);
                    println!("  Secondary Software ID: 0x{:x}", m.secondary_software_id);
                    let hash_algo = match m.hash_table_algorithm {
                        2 => "SHA256",
                        3 => "SHA384",
                        5 => "SHA512",
                        _ => "NA/Unknown",
                    };
                    println!("  Hash Table Algorithm: {} ({})", hash_algo, m.hash_table_algorithm);
                    println!("  Measurement Register Target: {}", m.measurement_register_target);
                }
                CommonMetadata::V01(m) => {
                    println!("  Software ID: 0x{:x}", m.base.software_id);
                    println!("  Secondary Software ID: 0x{:x}", m.base.secondary_software_id);
                    let hash_algo = match m.base.hash_table_algorithm {
                        2 => "SHA256",
                        3 => "SHA384",
                        5 => "SHA512",
                        _ => "NA/Unknown",
                    };
                    println!("  Hash Table Algorithm: {} ({})", hash_algo, m.base.hash_table_algorithm);
                    println!("  Measurement Register Target: {}", m.base.measurement_register_target);
                    println!("  ZI Segment Hash Algorithm: {}", m.zi_segment_hash_algorithm);
                }
            }
            println!();
        }

        if let Some(ref om) = ht.oem_metadata {
            println!("OEM Metadata:");
            println!("  Version: {}", om.get_version_string());
            println!("  Anti-Rollback Version: {}", om.get_arb_version());
            match om {
                Metadata::V00(m) => {
                    println!("  Software ID: 0x{:x}", m.software_id);
                    println!("  OEM ID: 0x{:x}", m.oem_id);
                    println!("  OEM Product ID: 0x{:x}", m.oem_product_id);
                    println!("  MRC Index: {}", m.mrc_index);
                    println!("  Secondary Software ID: 0x{:x}", m.secondary_software_id);
                    println!("  Flags: 0x{:x}", m.flags);
                }
                Metadata::V10(m) => {
                    println!("  Software ID: 0x{:x}", m.base.software_id);
                    println!("  OEM ID: 0x{:x}", m.base.oem_id);
                    println!("  OEM Product ID: 0x{:x}", m.base.oem_product_id);
                    println!("  MRC Index: {}", m.base.mrc_index);
                    println!("  Secondary Software ID: 0x{:x}", m.base.secondary_software_id);
                    println!("  Flags: 0x{:x}", m.base.flags);
                }
                Metadata::V20(m) => {
                    println!("  SoC Feature ID: 0x{:x}", m.soc_feature_id);
                    println!("  OEM ID: 0x{:x}", m.oem_id);
                    println!("  OEM Product ID: 0x{:x}", m.oem_product_id);
                    println!("  MRC Index: {}", m.mrc_index);
                    println!("  SoC Lifecycle State: {}", m.soc_lifecycle_state);
                    println!("  OEM Lifecycle State: {}", m.oem_lifecycle_state);
                    println!("  OEM Root Cert Hash Algo: {}", m.oem_root_certificate_hash_algorithm);
                    println!("  JTAG ID: 0x{:x}", m.jtag_id);
                    println!("  Flags: 0x{:x}", m.flags);
                }
                Metadata::V30(m) => {
                    println!("  Product Segment ID: 0x{:x}", m.product_segment_id);
                    println!("  OEM ID: 0x{:x}", m.base.oem_id);
                    println!("  OEM Product ID: 0x{:x}", m.base.oem_product_id);
                    println!("  MRC Index: {}", m.base.mrc_index);
                    println!("  SoC Lifecycle State: {}", m.base.soc_lifecycle_state);
                    println!("  OEM Lifecycle State: {}", m.base.oem_lifecycle_state);
                    println!("  Flags: 0x{:x}", m.base.flags);
                }
                Metadata::V31(m) => {
                    println!("  Product Segment ID: 0x{:x}", m.base.product_segment_id);
                    println!("  OEM ID: 0x{:x}", m.base.base.oem_id);
                    println!("  OEM Product ID: 0x{:x}", m.base.base.oem_product_id);
                    println!("  MRC Index: {}", m.base.base.mrc_index);
                    println!("  SoC Lifecycle State: {}", m.base.base.soc_lifecycle_state);
                    println!("  OEM Lifecycle State: {}", m.base.base.oem_lifecycle_state);
                    println!("  Flags: 0x{:x}", m.base.base.flags);
                }
            }
            println!();
        }

        if ht.serial_num.is_some() || !ht.hashes.is_empty() {
            println!("Hash Table Contents:");
            if let Some(serial) = ht.serial_num {
                println!("  Serial Number: {}", serial);
            }
            for (idx, hash) in ht.hashes.iter().enumerate() {
                let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
                println!("  Hash[{}]: {}", idx, hash_hex);
            }
            println!();
        }

        if let Some(ref enc) = ht.encryption {
            println!("Encryption Parameters:");
            match &enc.etype {
                hash_segment::encryption::EncryptionType::Qbec(q) => {
                    println!("  Scheme: QBEC v{}", q.version);
                    println!("  Total Size: {} bytes", q.total_size);
                    println!(
                        "  Encrypting Entity: {} ({})",
                        qbec::encrypting_entity_str(q.encrypting_entity),
                        q.encrypting_entity
                    );
                    if let Some(order) = q.encryption_order {
                        println!(
                            "  Encryption Order: {} ({})",
                            qbec::encryption_order_str(order),
                            order
                        );
                    } else {
                        println!("  Encryption Order: Encrypted then Signed (v1 default)");
                    }
                    println!(
                        "  Key Management Params Size: {} bytes",
                        q.key_management_parameters_size
                    );
                    if let Some(ref name) = q.key_management_scheme_name {
                        println!(
                            "  Key Management Scheme: {} (id={})",
                            name,
                            q.key_management_scheme_id.unwrap_or(0)
                        );
                    }
                    println!(
                        "  Data Encryption Params Size: {} bytes",
                        q.data_encryption_parameters_size
                    );
                    if let Some(ref name) = q.data_encryption_scheme_name {
                        println!(
                            "  Data Encryption Scheme: {} (id={})",
                            name,
                            q.data_encryption_scheme_id.unwrap_or(0)
                        );
                    }
                    eprintln!(
                        "  ERROR: firmware is encrypted (QBEC) cannot parse"
                    );
                    eprintln!(
                        "  Reason: {} (order={:?})",
                        q.key_management_scheme_name.as_deref().unwrap_or("QBEC"),
                        q.encryption_order.map(|o| if o == 0 { "Encrypt-then-Sign" } else { "Sign-then-Encrypt" }).unwrap_or("v1 default"),
                    );
                }
                hash_segment::encryption::EncryptionType::Uie(u) => {
                    println!("  Scheme: UIE");
                    println!("  EPS Count: {}", u.num_eps);
                    println!("  EPS1 Offset: {}, Version: {}.{}", u.eps1_offset, u.eps1_major_version, u.eps1_minor_version);
                    if u.eps2_offset != 0 {
                        println!(
                            "  EPS2 Offset: {}, Version: {}.{}",
                            u.eps2_offset, u.eps2_major_version, u.eps2_minor_version
                        );
                    }
                    eprintln!(
                        "  ERROR: firmware is encrypted (UIE) cannot parse"
                    );
                }
            }
            println!();
        }
    }

    if let Some(arb_val) = arb {
        if arb_val <= ARB_VALUE_MAX {
            println!("Anti-Rollback Version: {}", arb_val);
        } else {
            eprintln!("Warning: ARB value {} exceeds expected maximum.", arb_val);
            println!("Anti-Rollback Version: {}", arb_val);
        }
    } else {
        println!("Anti-Rollback Version: not present");
    }
}

fn process_elf(
    data: &[u8],
    path: &str,
    debug: bool,
    fast_mode: bool,
    verify_mode: bool,
) -> anyhow::Result<()> {
    debug_step(debug, 1, 6, "Opening and validating ELF file");

    if data[elf_defs::EI_DATA] != ELFDATA2LSB {
        anyhow::bail!(Error::ElfEndiannessMismatch(data[elf_defs::EI_DATA]));
    }
    debug_detail(debug, "  Endianness: little-endian (OK)");

    if data.len() < 52 {
        anyhow::bail!(Error::ElfHeaderTruncated {
            len: data.len(),
            need: 52,
        });
    }

    let elf_header = ElfHeader::from_bytes(data).map_err(|e| anyhow::anyhow!("{}", e))?;
    let elf_class = elf_header.elf_class;
    if elf_class != elf_defs::ELFCLASS32 && elf_class != elf_defs::ELFCLASS64 {
        anyhow::bail!(Error::ElfClassUnsupported(elf_class));
    }

    debug_detail(debug, &format!(
        "  Class: {} | Entry: 0x{:x} | Machine: 0x{:x}",
        if elf_class == elf_defs::ELFCLASS32 { "ELF32" } else { "ELF64" },
        elf_header.e_entry,
        elf_header.e_machine,
    ));

    debug_step(debug, 2, 6, "Reading program headers");

    let parser = ElfParser::from_bytes(data).map_err(|e| anyhow::anyhow!("{}", e))?;
    let phdrs = &parser.program_headers;

    debug_detail(debug, &format!(
        "  Program headers: {} at offset 0x{:x}, each {} bytes",
        parser.header.e_phnum,
        parser.header.e_phoff,
        parser.header.e_phentsize,
    ));

    if debug {
        print_phdr_debug(phdrs, elf_class);
    }

    debug_step(debug, 3, 6, "Scanning for HASH segment");

    let hash_info = if let Some(hash_phdr) = parser.find_hash_segment() {
        let offset = hash_phdr.p_offset as usize;
        let seg_type = p_flags_os_segment_type(hash_phdr.p_flags);

        debug_detail(debug, &format!(
            "  Found candidate at offset=0x{:x}, filesz=0x{:x}, os_seg_type={}",
            offset,
            hash_phdr.p_filesz,
            seg_type,
        ));

        match HashSegmentInfo::parse(data, offset) {
            Ok(Some(info)) => {
                debug_detail(debug, &format!(
                    "  HASH segment version {}: cm_sz={}, qti_sz={}, oem_sz={}, hash_sz={}",
                    info.header.version(),
                    info.header.common_metadata_size(),
                    info.header.qti_metadata_size(),
                    info.header.oem_metadata_size(),
                    info.header.hash_table_size(),
                ));

                if let Some(ref cm) = info.common_metadata {
                    let algo_name = |id| match id {
                        2 => "SHA256", 3 => "SHA384", 5 => "SHA512", _ => "NA",
                    };
                    debug_detail(debug, &format!(
                        "  Common Metadata: v{}, hash_algo={}({})",
                        cm.get_version_string(),
                        algo_name(match cm {
                            CommonMetadata::V00(m) => m.hash_table_algorithm,
                            CommonMetadata::V01(m) => m.base.hash_table_algorithm,
                        }),
                        match cm {
                            CommonMetadata::V00(m) => m.hash_table_algorithm,
                            CommonMetadata::V01(m) => m.base.hash_table_algorithm,
                        },
                    ));
                } else {
                    debug_detail(debug, "  Common Metadata: absent");
                }

                if let Some(ref om) = info.oem_metadata {
                    debug_detail(debug, &format!(
                        "  OEM Metadata: v{}, ARB={}",
                        om.get_version_string(),
                        om.get_arb_version(),
                    ));
                } else {
                    debug_detail(debug, "  OEM Metadata: absent");
                }

                debug_detail(debug, &format!(
                    "  Hash table: {} entries, {} bytes",
                    info.hashes.len(),
                    info.hashes.len() * 32,
                ));

                if let Some(ref serial) = info.serial_num {
                    debug_detail(debug, &format!("  Serial number: {}", serial));
                }

                let s = info.signature_status();
                use crate::hash_segment::parser::SignatureStatus;
                match s {
                    SignatureStatus::Both => debug_detail(debug, "  Signed: Yes (QTI+OEM)"),
                    SignatureStatus::QtiOnly => debug_detail(debug, "  Signed: Yes (QTI only)"),
                    SignatureStatus::OemOnly => debug_detail(debug, "  Signed: Yes (OEM only)"),
                    SignatureStatus::Unsigned => debug_detail(debug, "  Signed: No"),
                }

                if let Some(ref enc) = info.encryption {
                    eprintln!(
                        "[ERROR] firmware is encrypted ({}) cannot parse further",
                        enc.scheme_name()
                    );
                } else {
                    debug_detail(debug, "  Encryption: none");
                }

                Some(info)
            }
            Ok(None) => {
                debug_detail(debug, "  HASH segment header found but plausibility check failed");
                None
            }
            Err(e) => {
                eprintln!("[WARN] Hash segment parse encountered an issue: {e}");
                None
            }
        }
    } else {
        debug_detail(debug, "  No HASH segment found (no PHDR with OS segment type 2)");
        None
    };

    let arb = hash_info.as_ref().and_then(|ht| ht.get_arb_version());

    debug_step(debug, 4, 6, "Extracting anti-rollback version");
    match arb {
        Some(v) if v <= ARB_VALUE_MAX => debug_detail(debug, &format!("  ARB = {}", v)),
        Some(v) => debug_detail(debug, &format!("  ARB = {} (exceeds max {})", v, ARB_VALUE_MAX)),
        None => debug_detail(debug, "  ARB: not present in OEM metadata"),
    }

    debug_step(debug, 5, 6, "Verifying segment hashes");
    if verify_mode || debug {
        if let Some(ref ht) = hash_info {
            if ht.hashes.is_empty() {
                debug_detail(debug, "  Hash table empty, skipping verification");
            } else {
                let verifier = HashVerifier::new(data, phdrs, &parser.header);
                match verifier.verify(&ht.hashes, ht.common_metadata.as_ref()) {
                    Ok(()) => {
                        debug_detail(debug, "  All segment hashes match (OK)");
                        if verify_mode {
                            eprintln!("[VERIFY] All segment hashes match.");
                        }
                    }
                    Err(e) => {
                        debug_detail(debug, &format!("  Hash verification FAILED: {e}"));
                        eprintln!("[VERIFY] Hash verification failed: {}", e);
                        if verify_mode {
                            std::process::exit(1);
                        }
                    }
                }
            }
        } else if verify_mode {
            anyhow::bail!("No hash table found, cannot verify");
        } else {
            debug_detail(debug, "  No HASH segment, verification skipped");
        }
    }

    debug_step(debug, 6, 6, "Producing output");

    if fast_mode {
        if let Some(arb_val) = arb {
            if arb_val <= ARB_VALUE_MAX {
                println!("{}", arb_val);
            } else {
                eprintln!("Warning: ARB value {} exceeds expected maximum.", arb_val);
                println!("{}", arb_val);
            }
        } else {
            eprintln!("No ARB version found in the image.");
            if hash_info.is_some() {
                eprintln!("  Hint: HASH segment exists but lacks OEM metadata with anti_rollback_version.");
                eprintln!("  Possible reasons: No OEM metadata present, or metadata version is unrecognized.");
            } else {
                eprintln!("  Hint: No HASH segment found in this ELF image.");
                eprintln!("  Possible reasons: Image is not a Qualcomm secure ELF, or uses an older format.");
            }
            std::process::exit(1);
        }
    } else {
        print_full_output(path, data, &parser.header, phdrs, hash_info.as_ref(), arb, elf_class);
    }

    Ok(())
}

fn hash_table_end(info: &HashSegmentInfo, base_offset: usize) -> usize {
    let hdr_size = hs_defs::hash_table_header_size(info.header.version());
    base_offset + hdr_size
        + info.header.common_metadata_size() as usize
        + info.header.qti_metadata_size() as usize
        + info.header.oem_metadata_size() as usize
        + info.header.hash_table_size() as usize
}

fn debug_step(debug: bool, step: usize, total: usize, label: &str) {
    if debug {
        eprintln!("[DEBUG] ── Step {}/{}: {} ──", step, total, label);
    }
}

fn debug_detail(debug: bool, msg: &str) {
    if debug {
        eprintln!("[DEBUG] {}", msg);
    }
}

fn process_mbn(data: &[u8], path: &str, debug: bool, fast_mode: bool) -> anyhow::Result<()> {
    debug_step(debug, 1, 3, "Reading MBN header");

    if data.len() < 8 {
        anyhow::bail!("MBN file too short: {} bytes, need at least 8", data.len());
    }

    let version = data::read_le_u32(data, 4);
    debug_detail(debug, &format!("  Detected MBN version: {}", version));

    if !hs_defs::is_valid_hash_segment_version(version) {
        anyhow::bail!(Error::MbnUnsupportedVersion(version));
    }

    let mbn_parser = mbn::parser::MbnParser::from_bytes(data).map_err(|e| anyhow::anyhow!("{}", e))?;
    let header = &mbn_parser.header;

    debug_step(debug, 2, 3, "Extracting image info");
    debug_detail(debug, &format!(
        "  Image ID: 0x{:x} | Code size: {} | Image size: {}",
        header.image_id(),
        header.code_size(),
        header.image_size(),
    ));

    debug_step(debug, 3, 3, "Producing output");

    if fast_mode {
        println!("MBN format does not contain ARB field");
    } else {
        println!("File: {}", path);
        println!("Format: MBN v{}", header.version());
        println!("Image ID: 0x{:x}", header.image_id());
        println!("Code size: {} bytes", header.code_size());
        println!("Image size: {} bytes", header.image_size());
        println!("ARB: not applicable");
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "secure-image" {
        let secure_args = cli::secure_image::handler::parse_secure_image_args(&args[1..])?;
        return handler::handle_secure_image(secure_args)
            .map_err(|e| anyhow::anyhow!("{}", e));
    }

    let mut debug = false;
    let mut fast_mode = false;
    let mut verify_mode = false;
    let mut path = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--debug" | "-d" => {
                debug = true;
                i += 1;
            }
            "--fast" | "-a" => {
                fast_mode = true;
                i += 1;
            }
            "--verify" => {
                verify_mode = true;
                i += 1;
            }
            "--version" | "-v" => {
                println!("arb_inspector_next v{}", VERSION);
                return Ok(());
            }
            "--help" | "-h" => {
                cli::secure_image::cmdline_dict::print_help();
                return Ok(());
            }
            _ => {
                if path.is_none() {
                    path = Some(args[i].clone());
                    i += 1;
                } else {
                    anyhow::bail!("Usage: {} [--debug] [--fast] [--verify] [-v] <image>", args[0]);
                }
            }
        }
    }

    let path = path.context("No input file provided")?;

    let mut file = File::open(&path)?;
    let mut header_buf = [0u8; 64];
    file.read_exact(&mut header_buf)?;

    match detect_file_type(&header_buf) {
        FileType::Elf => {
            file.seek(SeekFrom::Start(0))?;
            let mut full_data = Vec::new();
            file.read_to_end(&mut full_data)?;
            process_elf(&full_data, &path, debug, fast_mode, verify_mode)?;
        }
        FileType::Mbn => {
            file.seek(SeekFrom::Start(0))?;
            let mut full_data = Vec::new();
            file.read_to_end(&mut full_data)?;
            process_mbn(&full_data, &path, debug, fast_mode)?;
        }
        FileType::Unknown => {
            anyhow::bail!("Unknown file format (not ELF or MBN)");
        }
    }

    Ok(())
}
