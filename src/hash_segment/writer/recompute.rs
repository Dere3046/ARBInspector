use crate::config::profile::HashAlgorithm;
use crate::elf::defines::{
    p_flags_os_access_type, p_flags_os_page_mode, p_flags_os_segment_type, ELF_BLOCK_ALIGN,
    P_FLAGS_OS_SEGMENT_HASH, PF_OS_ACCESS_NOTUSED, PF_OS_ACCESS_SHARED,
    PF_OS_NON_PAGED_SEGMENT, PF_OS_PAGED_SEGMENT,
};
use crate::elf::header::ElfHeader;
use crate::elf::program_header::ProgramHeader;
use crate::error::Result;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub fn compute_segment_hashes(
    elf_data: &[u8],
    program_headers: &[ProgramHeader],
    elf_header: &ElfHeader,
    algo: HashAlgorithm,
) -> Result<Vec<Vec<u8>>> {
    let mut hashes = Vec::new();

    for phdr in program_headers {
        let flags = phdr.p_flags;
        let os_seg_type = p_flags_os_segment_type(flags);
        if os_seg_type == P_FLAGS_OS_SEGMENT_HASH {
            continue;
        }

        let os_access = p_flags_os_access_type(flags);
        if os_access == PF_OS_ACCESS_NOTUSED || os_access == PF_OS_ACCESS_SHARED {
            hashes.push(vec![0u8; algo.digest_size()]);
            continue;
        }

        if phdr.p_filesz == 0 {
            hashes.push(vec![0u8; algo.digest_size()]);
            continue;
        }

        let seg_data = if phdr.p_type == 6 {
            let start = elf_header.e_phoff as usize;
            let end = start
                + (elf_header.e_phnum as usize * elf_header.e_phentsize as usize);
            if end <= elf_data.len() {
                &elf_data[start..end]
            } else {
                &[]
            }
        } else {
            let start = phdr.p_offset as usize;
            let end = start + phdr.p_filesz as usize;
            if end <= elf_data.len() {
                &elf_data[start..end]
            } else {
                &[]
            }
        };

        let page_mode = p_flags_os_page_mode(flags);
        if page_mode == PF_OS_NON_PAGED_SEGMENT {
            let hash = hash_data(seg_data, algo);
            hashes.push(hash);
        } else if page_mode == PF_OS_PAGED_SEGMENT {
            let mut offset = 0;
            let nonalign = phdr.p_vaddr & (ELF_BLOCK_ALIGN - 1);
            if nonalign != 0 {
                offset = (ELF_BLOCK_ALIGN - nonalign) as usize;
            }
            let mut page_data = seg_data;
            if offset < page_data.len() {
                page_data = &page_data[offset..];
            } else {
                continue;
            }
            while page_data.len() >= ELF_BLOCK_ALIGN as usize {
                let hash = hash_data(&page_data[..ELF_BLOCK_ALIGN as usize], algo);
                hashes.push(hash);
                page_data = &page_data[ELF_BLOCK_ALIGN as usize..];
            }
        }
    }

    Ok(hashes)
}

fn hash_data(data: &[u8], algo: HashAlgorithm) -> Vec<u8> {
    match algo {
        HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
    }
}
