use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use sha2::{Sha256, Digest};

mod elf;
mod hash_segment;
mod metadata;
mod mbn;

use elf::*;
use hash_segment::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const OS_TYPE_HASH: u32 = 0x2;

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

fn compute_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct HashTableSegmentHeader {
    reserved: u32,
    version: u32,
    common_metadata_size: u32,
    qti_metadata_size: u32,
    oem_metadata_size: u32,
    hash_table_size: u32,
    qti_sig_size: u32,
    qti_cert_chain_size: u32,
    oem_sig_size: u32,
    oem_cert_chain_size: u32,
}

impl HashTableSegmentHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < HASH_TABLE_HEADER_SIZE {
            return Err("Insufficient data for hash table header");
        }
        Ok(Self {
            reserved: read_le_u32(data, 0),
            version: read_le_u32(data, 4),
            common_metadata_size: read_le_u32(data, 8),
            qti_metadata_size: read_le_u32(data, 12),
            oem_metadata_size: read_le_u32(data, 16),
            hash_table_size: read_le_u32(data, 20),
            qti_sig_size: read_le_u32(data, 24),
            qti_cert_chain_size: read_le_u32(data, 28),
            oem_sig_size: read_le_u32(data, 32),
            oem_cert_chain_size: read_le_u32(data, 36),
        })
    }

    fn is_plausible(&self) -> bool {
        let common_sz = self.common_metadata_size as usize;
        let qti_sz = self.qti_metadata_size as usize;
        let oem_sz = self.oem_metadata_size as usize;
        let hash_sz = self.hash_table_size as usize;

        (VERSION_MIN..=VERSION_MAX).contains(&self.version) &&
        common_sz <= COMMON_SIZE_MAX &&
        qti_sz <= QTI_SIZE_MAX &&
        oem_sz <= OEM_SIZE_MAX &&
        hash_sz > 0 && hash_sz <= HASH_TABLE_SIZE_MAX
    }

    fn header_size(&self) -> usize {
        HASH_TABLE_HEADER_SIZE
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Elf32ProgramHeader {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
}

impl Elf32ProgramHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF32_PHDR_SIZE {
            return Err("Insufficient data for ELF32 program header");
        }
        Ok(Self {
            p_type: read_le_u32(data, 0),
            p_offset: read_le_u32(data, 4),
            p_vaddr: read_le_u32(data, 8),
            p_paddr: read_le_u32(data, 12),
            p_filesz: read_le_u32(data, 16),
            p_memsz: read_le_u32(data, 20),
            p_flags: read_le_u32(data, 24),
            p_align: read_le_u32(data, 28),
        })
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Elf64ProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

impl Elf64ProgramHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF64_PHDR_SIZE {
            return Err("Insufficient data for ELF64 program header");
        }
        Ok(Self {
            p_type: read_le_u32(data, 0),
            p_flags: read_le_u32(data, 4),
            p_offset: read_le_u64(data, 8),
            p_vaddr: read_le_u64(data, 16),
            p_paddr: read_le_u64(data, 24),
            p_filesz: read_le_u64(data, 32),
            p_memsz: read_le_u64(data, 40),
            p_align: read_le_u64(data, 48),
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct ElfInfo {
    elf_class: u8,
    e_entry: u64,
    e_phoff: u64,
    e_phnum: u16,
    e_phentsize: u16,
    e_flags: u32,
    e_machine: u16,
    e_type: u16,
}

#[derive(Debug)]
#[allow(dead_code)]
struct ProgramHeaderInfo {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

#[derive(Debug)]
struct HashTableInfo {
    header: HashTableSegmentHeader,
    common_metadata: Option<metadata::CommonMetadata>,
    oem_metadata: Option<metadata::Metadata>,
    serial_num: Option<u32>,
    hashes: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct ElfWithHashTable {
    elf_info: ElfInfo,
    program_headers: Vec<ProgramHeaderInfo>,
    hash_table_info: Option<HashTableInfo>,
}

impl ElfWithHashTable {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 || &data[0..4] != &ELF_MAGIC {
            return Err("Invalid ELF magic");
        }

        let elf_class = data[EI_CLASS];
        let elf_info = match elf_class {
            ELFCLASS32 => {
                if data.len() < ELF32_HDR_SIZE {
                    return Err("Insufficient data for ELF32 header");
                }
                ElfInfo {
                    elf_class,
                    e_type: read_le_u16(data, 16),
                    e_machine: read_le_u16(data, 18),
                    e_entry: read_le_u32(data, 24) as u64,
                    e_phoff: read_le_u32(data, 28) as u64,
                    e_flags: read_le_u32(data, 36),
                    e_phnum: read_le_u16(data, 44),
                    e_phentsize: read_le_u16(data, 42),
                }
            }
            ELFCLASS64 => {
                if data.len() < ELF64_HDR_SIZE {
                    return Err("Insufficient data for ELF64 header");
                }
                ElfInfo {
                    elf_class,
                    e_type: read_le_u16(data, 16),
                    e_machine: read_le_u16(data, 18),
                    e_entry: read_le_u64(data, 24),
                    e_phoff: read_le_u64(data, 32),
                    e_flags: read_le_u32(data, 48),
                    e_phnum: read_le_u16(data, 56),
                    e_phentsize: read_le_u16(data, 54),
                }
            }
            _ => return Err("Unsupported ELF class"),
        };

        let mut program_headers = Vec::with_capacity(elf_info.e_phnum as usize);
        for i in 0..elf_info.e_phnum {
            let offset = (elf_info.e_phoff + (i as u64) * (elf_info.e_phentsize as u64)) as usize;
            if offset + (elf_info.e_phentsize as usize) > data.len() {
                continue;
            }

            let phdr_info = match elf_class {
                ELFCLASS32 => {
                    let phdr = Elf32ProgramHeader::from_bytes(&data[offset..offset + ELF32_PHDR_SIZE])?;
                    ProgramHeaderInfo {
                        p_type: phdr.p_type,
                        p_flags: phdr.p_flags,
                        p_offset: phdr.p_offset as u64,
                        p_vaddr: phdr.p_vaddr as u64,
                        p_paddr: phdr.p_paddr as u64,
                        p_filesz: phdr.p_filesz as u64,
                        p_memsz: phdr.p_memsz as u64,
                    }
                }
                ELFCLASS64 => {
                    let phdr = Elf64ProgramHeader::from_bytes(&data[offset..offset + ELF64_PHDR_SIZE])?;
                    ProgramHeaderInfo {
                        p_type: phdr.p_type,
                        p_flags: phdr.p_flags,
                        p_offset: phdr.p_offset,
                        p_vaddr: phdr.p_vaddr,
                        p_paddr: phdr.p_paddr,
                        p_filesz: phdr.p_filesz,
                        p_memsz: phdr.p_memsz,
                    }
                }
                _ => unreachable!(),
            };
            program_headers.push(phdr_info);
        }

        let mut hash_table_info = None;

        for phdr in &program_headers {
            let os_type = get_os_segment_type(phdr.p_flags);
            if os_type == OS_TYPE_HASH {
                let p_offset = phdr.p_offset as usize;
                let p_filesz = phdr.p_filesz as usize;

                if p_offset + p_filesz <= data.len() && p_filesz >= HASH_TABLE_HEADER_SIZE {
                    if let Ok(ht_header) = HashTableSegmentHeader::from_bytes(&data[p_offset..p_offset + HASH_TABLE_HEADER_SIZE_V7]) {
                        if ht_header.is_plausible() {
                            let header_size = ht_header.header_size();
                            let mut offset = p_offset + header_size;

                            let mut common_metadata = None;
                            let mut oem_metadata = None;
                            let mut serial_num = None;
                            let mut hashes = Vec::new();

                            if ht_header.common_metadata_size > 0 && offset + ht_header.common_metadata_size as usize <= data.len() {
                                let cm_data = &data[offset..offset + ht_header.common_metadata_size as usize];
                                if cm_data.len() >= 8 {
                                    let cm_major = read_le_u32(cm_data, 0);
                                    let cm_minor = read_le_u32(cm_data, 4);
                                    if let Ok(cm) = metadata::CommonMetadata::from_bytes(cm_data, cm_major, cm_minor) {
                                        common_metadata = Some(cm);
                                    }
                                }
                                offset += ht_header.common_metadata_size as usize;
                            }

                            if ht_header.oem_metadata_size > 0 && offset + ht_header.oem_metadata_size as usize <= data.len() {
                                let oem_data = &data[offset..offset + ht_header.oem_metadata_size as usize];
                                if oem_data.len() >= 12 {
                                    let oem_major = read_le_u32(oem_data, 0);
                                    let oem_minor = read_le_u32(oem_data, 4);
                                    let arb_candidate = read_le_u32(oem_data, 8);
                                    
                                    if ht_header.version == 7 && oem_data.len() >= 12 && arb_candidate <= ARB_VALUE_MAX {
                                        oem_metadata = Some(metadata::Metadata::V20(metadata::MetadataV20 {
                                            major_version: oem_major,
                                            minor_version: oem_minor,
                                            anti_rollback_version: arb_candidate,
                                            mrc_index: if oem_data.len() > 12 { read_le_u32(oem_data, 12) } else { 0 },
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
                                    } else if let Ok(om) = metadata::Metadata::from_bytes(oem_data, oem_major, oem_minor) {
                                        oem_metadata = Some(om);
                                    }
                                }
                            }

                            let hash_table_offset = offset;
                            let hash_table_size = ht_header.hash_table_size as usize;
                            if hash_table_offset + hash_table_size <= data.len() && hash_table_size > 0 {
                                let hash_table = &data[hash_table_offset..hash_table_offset + hash_table_size];
                                
                                let hash_size = SHA256_SIZE;
                                let mut ht_offset = 0;

                                if hash_table.len() >= hash_size * 2 {
                                    let potential_serial = read_le_u32(&hash_table, hash_size);
                                    let mut is_valid_serial = true;
                                    for i in 0..hash_size {
                                        if hash_table[i] != 0 {
                                            is_valid_serial = false;
                                            break;
                                        }
                                    }
                                    if is_valid_serial && potential_serial != 0 {
                                        serial_num = Some(potential_serial);
                                        ht_offset = hash_size * 2;
                                    }
                                }

                                while ht_offset + hash_size <= hash_table.len() {
                                    let hash = hash_table[ht_offset..ht_offset + hash_size].to_vec();
                                    hashes.push(hash);
                                    ht_offset += hash_size;
                                }
                            }

                            hash_table_info = Some(HashTableInfo {
                                header: ht_header,
                                common_metadata,
                                oem_metadata,
                                serial_num,
                                hashes,
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(Self {
            elf_info,
            program_headers,
            hash_table_info,
        })
    }

    fn get_arb_version(&self) -> Option<u32> {
        self.hash_table_info.as_ref().and_then(|ht| {
            ht.oem_metadata.as_ref().map(|m| m.get_arb_version())
        })
    }

    fn compute_segment_hashes(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
        let mut hashes = Vec::new();

        for phdr in &self.program_headers {
            let flags = phdr.p_flags;
            let os_seg_type = get_os_segment_type(flags);
            let os_access = get_os_access_type(flags);
            let os_page_mode = get_os_page_mode(flags);

            if os_seg_type == PF_OS_SEGMENT_HASH {
                continue;
            }

            if os_access == PF_OS_ACCESS_NOTUSED || os_access == PF_OS_ACCESS_SHARED {
                hashes.push(vec![0u8; SHA256_SIZE]);
                continue;
            }

            if phdr.p_filesz == 0 {
                hashes.push(vec![0u8; SHA256_SIZE]);
                continue;
            }

            let seg_data = if phdr.p_type == PT_PHDR {
                let start = self.elf_info.e_phoff as usize;
                let end = start + (self.elf_info.e_phnum as usize * self.elf_info.e_phentsize as usize);
                if end <= data.len() {
                    &data[start..end]
                } else {
                    &[]
                }
            } else {
                let start = phdr.p_offset as usize;
                let end = start + phdr.p_filesz as usize;
                if end <= data.len() {
                    &data[start..end]
                } else {
                    &[]
                }
            };

            if os_page_mode == PF_OS_NON_PAGED_SEGMENT {
                let hash = compute_sha256(seg_data);
                hashes.push(hash);
            } else if os_page_mode == PF_OS_PAGED_SEGMENT {
                let mut offset = 0;
                let nonalign = phdr.p_vaddr & (ELF_BLOCK_ALIGN - 1);
                if nonalign != 0 {
                    offset = (ELF_BLOCK_ALIGN - nonalign) as usize;
                }

                let mut page_data = seg_data;
                if offset < page_data.len() {
                    page_data = &page_data[offset..];
                }

                while page_data.len() >= ELF_BLOCK_ALIGN as usize {
                    let hash = compute_sha256(&page_data[..ELF_BLOCK_ALIGN as usize]);
                    hashes.push(hash);
                    page_data = &page_data[ELF_BLOCK_ALIGN as usize..];
                }
            }
        }

        Ok(hashes)
    }
}

enum FileType {
    Elf,
    Mbn,
    Unknown,
}

fn detect_file_type(data: &[u8]) -> FileType {
    if data.starts_with(&ELF_MAGIC) {
        FileType::Elf
    } else if data.len() >= 8 {
        let version = read_le_u32(data, 4);
        if [3, 5, 6, 7, 8].contains(&version) {
            FileType::Mbn
        } else {
            FileType::Unknown
        }
    } else {
        FileType::Unknown
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut debug = false;
    let mut quick_mode = false;
    let mut full_mode = false;
    let mut path = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--debug" | "-d" => {
                debug = true;
                i += 1;
            }
            "--quick" | "-q" => {
                quick_mode = true;
                i += 1;
            }
            "--full" | "-f" => {
                full_mode = true;
                i += 1;
            }
            "--version" | "-v" => {
                println!("arb_inspector_next version {}", VERSION);
                return Ok(());
            }
            _ => {
                if path.is_none() {
                    path = Some(args[i].clone());
                    i += 1;
                } else {
                    eprintln!("Usage: {} [--debug] [--quick|--full] [-v] <image>", args[0]);
                    std::process::exit(1);
                }
            }
        }
    }

    if !quick_mode && !full_mode {
        quick_mode = true;
    }

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("Usage: {} [--debug] [--quick|--full] [-v] <image>", args[0]);
            std::process::exit(1);
        }
    };

    let mut file = File::open(&path)?;
    let mut header_buf = [0u8; 64];
    file.read_exact(&mut header_buf)?;

    match detect_file_type(&header_buf) {
        FileType::Elf => {
            if debug {
                eprintln!("[DEBUG] Detected ELF file");
            }

            if header_buf[EI_DATA] != ELFDATA2LSB {
                return Err("Not a little-endian ELF file".into());
            }

            let elf_class = header_buf[EI_CLASS];
            if elf_class != ELFCLASS32 && elf_class != ELFCLASS64 {
                return Err("Unsupported ELF class".into());
            }

            if debug {
                eprintln!("[DEBUG] ELF class: {}", if elf_class == ELFCLASS32 { "32-bit" } else { "64-bit" });
            }

            file.seek(SeekFrom::Start(0))?;
            let mut full_data = Vec::new();
            file.read_to_end(&mut full_data)?;

            if debug {
                eprintln!("[DEBUG] Full ELF size: {} bytes", full_data.len());
            }

            let elf_with_hash = ElfWithHashTable::from_bytes(&full_data)?;

            if debug {
                eprintln!("[DEBUG] ELF entry: 0x{:x}", elf_with_hash.elf_info.e_entry);
                eprintln!("[DEBUG] Program header offset: 0x{:x}", elf_with_hash.elf_info.e_phoff);
                eprintln!("[DEBUG] Program header count: {}", elf_with_hash.elf_info.e_phnum);
                eprintln!("[DEBUG] Program header size: {} bytes", elf_with_hash.elf_info.e_phentsize);

                for (i, ph) in elf_with_hash.program_headers.iter().enumerate() {
                    let flags = ph.p_flags;
                    let perm = get_perm_value(flags);
                    let os_seg = get_os_segment_type(flags);
                    let os_access = get_os_access_type(flags);
                    let os_page = get_os_page_mode(flags);
                    eprintln!("[DEBUG] PH[{}]: type={:#x} offset=0x{:x} filesz=0x{:x} flags={:#x}",
                        i, ph.p_type, ph.p_offset, ph.p_filesz, flags);
                    eprintln!("[DEBUG]        Perm: {} OS_Seg: {} OS_Access: {} Page: {}",
                        perm_to_string(perm), os_segment_type_to_string(os_seg),
                        os_access_type_to_string(os_access), os_page_mode_to_string(os_page));
                }

                match elf_with_hash.compute_segment_hashes(&full_data) {
                    Ok(computed_hashes) => {
                        eprintln!("[DEBUG] Computed {} segment hashes:", computed_hashes.len());
                        for (i, h) in computed_hashes.iter().enumerate() {
                            eprintln!("[DEBUG]   Hash[{}]: {}", i, h.iter().map(|b| format!("{:02x}", b)).collect::<String>());
                        }
                    }
                    Err(e) => eprintln!("[DEBUG] Failed to compute segment hashes: {}", e),
                }
            }

            let arb = elf_with_hash.get_arb_version();

            if debug {
                if let Some(ref ht) = elf_with_hash.hash_table_info {
                    eprintln!("[DEBUG] Found HASH segment header:");
                    eprintln!("[DEBUG]   version: {}", ht.header.version);
                    eprintln!("[DEBUG]   common_metadata_size: {}", ht.header.common_metadata_size);
                    eprintln!("[DEBUG]   oem_metadata_size: {}", ht.header.oem_metadata_size);
                    eprintln!("[DEBUG]   hash_table_size: {}", ht.header.hash_table_size);
                } else {
                    eprintln!("[DEBUG] No HASH segment header found");
                }

                if let Some(arb_val) = arb {
                    eprintln!("[DEBUG] Extracted ARB: {}", arb_val);
                }
            }

            if quick_mode {
                if let Some(arb_val) = arb {
                    if arb_val <= ARB_VALUE_MAX {
                        println!("{}", arb_val);
                    } else {
                        eprintln!("Warning: ARB value {} exceeds expected maximum.", arb_val);
                        println!("{}", arb_val);
                    }
                } else {
                    eprintln!("No ARB version found in the image");
                    std::process::exit(1);
                }
            } else if full_mode {
                println!("File: {}", path);
                println!("Format: ELF ({})", if elf_class == ELFCLASS32 { "32-bit" } else { "64-bit" });
                println!("Entry point: 0x{:x}", elf_with_hash.elf_info.e_entry);
                println!("Machine: 0x{:x}", elf_with_hash.elf_info.e_machine);
                println!("Type: 0x{:x}", elf_with_hash.elf_info.e_type);
                println!("Flags: 0x{:x}", elf_with_hash.elf_info.e_flags);
                println!("Program headers: {}", elf_with_hash.elf_info.e_phnum);
                println!();

                println!("Program Headers:");
                for (i, phdr) in elf_with_hash.program_headers.iter().enumerate() {
                    let flags = phdr.p_flags;
                    let perm = get_perm_value(flags);
                    let os_seg_type = get_os_segment_type(flags);
                    let os_access = get_os_access_type(flags);
                    let os_page_mode = get_os_page_mode(flags);

                    println!("  [{}] Type: {} Offset: 0x{:x} VAddr: 0x{:x} FileSize: 0x{:x} MemSize: 0x{:x}",
                        i,
                        p_type_to_string(phdr.p_type),
                        phdr.p_offset,
                        phdr.p_vaddr,
                        phdr.p_filesz,
                        phdr.p_memsz);
                    println!("      Flags: {:#x} Perm: {} OS_Type: {} OS_Access: {} Page_Mode: {}",
                        flags,
                        perm_to_string(perm),
                        os_segment_type_to_string(os_seg_type),
                        os_access_type_to_string(os_access),
                        os_page_mode_to_string(os_page_mode));
                }
                println!();

                if let Some(ref ht) = elf_with_hash.hash_table_info {
                    println!("Hash Table Segment Header:");
                    println!("  Version: {}", ht.header.version);
                    println!("  Common Metadata Size: {} (bytes)", ht.header.common_metadata_size);
                    println!("  QTI Metadata Size: {} (bytes)", ht.header.qti_metadata_size);
                    println!("  OEM Metadata Size: {} (bytes)", ht.header.oem_metadata_size);
                    println!("  Hash Table Size: {} (bytes)", ht.header.hash_table_size);
                    println!("  QTI Signature Size: {} (bytes)", ht.header.qti_sig_size);
                    println!("  QTI Cert Chain Size: {} (bytes)", ht.header.qti_cert_chain_size);
                    println!("  OEM Signature Size: {} (bytes)", ht.header.oem_sig_size);
                    println!("  OEM Cert Chain Size: {} (bytes)", ht.header.oem_cert_chain_size);
                    println!();

                    if let Some(ref cm) = ht.common_metadata {
                        println!("Common Metadata:");
                        println!("  Version: {}", cm.get_version_string());
                        match cm {
                            metadata::CommonMetadata::V00(m) => {
                                println!("  One-shot Hash Algorithm: {}", m.one_shot_hash_algorithm);
                                println!("  Segment Hash Algorithm: {}", m.segment_hash_algorithm);
                            }
                            metadata::CommonMetadata::V01(m) => {
                                println!("  One-shot Hash Algorithm: {}", m.base.one_shot_hash_algorithm);
                                println!("  Segment Hash Algorithm: {}", m.base.segment_hash_algorithm);
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
                            metadata::Metadata::V00(m) => {
                                println!("  Software ID: 0x{:x}", m.software_id);
                                println!("  OEM ID: 0x{:x}", m.oem_id);
                                println!("  OEM Product ID: 0x{:x}", m.oem_product_id);
                                println!("  MRC Index: {}", m.mrc_index);
                                println!("  Debug: {}", m.debug);
                                println!("  Secondary Software ID: 0x{:x}", m.secondary_software_id);
                                println!("  Flags: 0x{:x}", m.flags);
                            }
                            metadata::Metadata::V10(m) => {
                                println!("  Software ID: 0x{:x}", m.base.software_id);
                                println!("  OEM ID: 0x{:x}", m.base.oem_id);
                                println!("  OEM Product ID: 0x{:x}", m.base.oem_product_id);
                                println!("  MRC Index: {}", m.base.mrc_index);
                                println!("  Debug: {}", m.base.debug);
                                println!("  Secondary Software ID: 0x{:x}", m.base.secondary_software_id);
                                println!("  Flags: 0x{:x}", m.base.flags);
                                println!("  In-use JTAG ID: {}", m.in_use_jtag_id);
                                println!("  OEM Product ID Independent: {}", m.oem_product_id_independent);
                            }
                            metadata::Metadata::V20(m) => {
                                println!("  SoC Feature ID: 0x{:x}", m.soc_feature_id);
                                println!("  OEM ID: 0x{:x}", m.oem_id);
                                println!("  OEM Product ID: 0x{:x}", m.oem_product_id);
                                println!("  MRC Index: {}", m.mrc_index);
                                println!("  SoC Lifecycle State: {}", m.soc_lifecycle_state);
                                println!("  OEM Lifecycle State: {}", m.oem_lifecycle_state);
                                println!("  OEM Root Cert Hash Algo: {}", m.oem_root_certificate_hash_algorithm);
                                println!("  Flags: 0x{:x}", m.flags);
                            }
                            metadata::Metadata::V30(m) => {
                                println!("  SoC Feature ID: 0x{:x}", m.base.soc_feature_id);
                                println!("  OEM ID: 0x{:x}", m.base.oem_id);
                                println!("  OEM Product ID: 0x{:x}", m.base.oem_product_id);
                                println!("  MRC Index: {}", m.base.mrc_index);
                                println!("  SoC Lifecycle State: {}", m.base.soc_lifecycle_state);
                                println!("  OEM Lifecycle State: {}", m.base.oem_lifecycle_state);
                                println!("  QTI Lifecycle State: {}", m.qti_lifecycle_state);
                                println!("  Flags: 0x{:x}", m.base.flags);
                            }
                            metadata::Metadata::V31(m) => {
                                println!("  SoC Feature ID: 0x{:x}", m.base.base.soc_feature_id);
                                println!("  OEM ID: 0x{:x}", m.base.base.oem_id);
                                println!("  OEM Product ID: 0x{:x}", m.base.base.oem_product_id);
                                println!("  MRC Index: {}", m.base.base.mrc_index);
                                println!("  SoC Lifecycle State: {}", m.base.base.soc_lifecycle_state);
                                println!("  OEM Lifecycle State: {}", m.base.base.oem_lifecycle_state);
                                println!("  QTI Lifecycle State: {}", m.base.qti_lifecycle_state);
                                println!("  Measurement Register Target: {}", m.measurement_register_target);
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
                            let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                            println!("  Hash[{}]: {}", idx, hash_hex);
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
        }

        FileType::Mbn => {
            if debug {
                eprintln!("[DEBUG] Detected MBN file");
            }
            file.seek(SeekFrom::Start(0))?;
            let mut full_data = Vec::new();
            file.read_to_end(&mut full_data)?;

            if debug {
                eprintln!("[DEBUG] Full MBN size: {} bytes", full_data.len());
            }

            let mbn = mbn::Mbn::from_bytes(&full_data)?;

            if debug {
                eprintln!("[DEBUG] MBN version: {}", mbn.header.version);
                eprintln!("[DEBUG] Image ID: 0x{:x}", mbn.header.image_id);
                eprintln!("[DEBUG] Code size: {}", mbn.header.code_size);
                eprintln!("[DEBUG] Image size: {}", mbn.header.image_size);
                eprintln!("[DEBUG] Signature ptr: 0x{:x}", mbn.header.sig_ptr);
                eprintln!("[DEBUG] Signature size: {}", mbn.header.sig_size);
                eprintln!("[DEBUG] Certificate chain ptr: 0x{:x}", mbn.header.cert_chain_ptr);
                eprintln!("[DEBUG] Certificate chain size: {}", mbn.header.cert_chain_size);
            }

            if quick_mode {
                println!("MBN format does not contain ARB field");
            } else if full_mode {
                println!("File: {}", path);
                println!("Format: MBN v{}", mbn.header.version);
                println!("Image ID: 0x{:x}", mbn.header.image_id);
                println!("Code size: {} bytes", mbn.header.code_size);
                println!("Image size: {} bytes", mbn.header.image_size);
                println!("Signature ptr: 0x{:x}, size: {}", mbn.header.sig_ptr, mbn.header.sig_size);
                println!("Certificate chain ptr: 0x{:x}, size: {}", mbn.header.cert_chain_ptr, mbn.header.cert_chain_size);
                println!("ARB: not applicable");
            }
        }

        FileType::Unknown => {
            return Err("Unknown file format (not ELF or MBN)".into());
        }
    }

    Ok(())
}
