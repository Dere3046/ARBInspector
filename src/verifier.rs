use crate::elf::*;
use crate::error::{Error, Result};
use crate::hash_segment::{SHA256_SIZE, SHA384_SIZE, SHA512_SIZE};
use crate::metadata::CommonMetadata;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub struct HashVerifier<'a> {
    elf_data: &'a [u8],
    program_headers: &'a [crate::ProgramHeaderInfo],
    elf_info: &'a crate::ElfInfo,
}

impl<'a> HashVerifier<'a> {
    pub fn new(
        elf_data: &'a [u8],
        program_headers: &'a [crate::ProgramHeaderInfo],
        elf_info: &'a crate::ElfInfo,
    ) -> Self {
        Self {
            elf_data,
            program_headers,
            elf_info,
        }
    }


    pub fn compute_segment_hashes(&self) -> Result<Vec<Vec<u8>>> {
        let mut hashes = Vec::new();

        for phdr in self.program_headers {
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
                let end = start
                    + (self.elf_info.e_phnum as usize * self.elf_info.e_phentsize as usize);
                if end <= self.elf_data.len() {
                    &self.elf_data[start..end]
                } else {
                    return Err(Error::HashVerification(
                        "PHDR segment extends beyond file bounds".into(),
                    ));
                }
            } else {
                let start = phdr.p_offset as usize;
                let end = start + phdr.p_filesz as usize;
                if end <= self.elf_data.len() {
                    &self.elf_data[start..end]
                } else {
                    return Err(Error::HashVerification(format!(
                        "Segment data out of bounds: offset 0x{:x} filesz 0x{:x}",
                        phdr.p_offset, phdr.p_filesz
                    )));
                }
            };


            if os_page_mode == PF_OS_NON_PAGED_SEGMENT {
                let hash = compute_hash(seg_data, HashAlgorithm::Sha256)?;
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
                } else {

                    continue;
                }

                while page_data.len() >= ELF_BLOCK_ALIGN as usize {
                    let hash = compute_hash(&page_data[..ELF_BLOCK_ALIGN as usize], HashAlgorithm::Sha256)?;
                    hashes.push(hash);
                    page_data = &page_data[ELF_BLOCK_ALIGN as usize..];
                }

            }
        }

        Ok(hashes)
    }


    pub fn verify(
        &self,
        stored_hashes: &[Vec<u8>],
        common_metadata: Option<&CommonMetadata>,
    ) -> Result<()> {
        let computed = self.compute_segment_hashes()?;

        if computed.len() != stored_hashes.len() {
            return Err(Error::HashVerification(format!(
                "Hash count mismatch: computed {} vs stored {}",
                computed.len(),
                stored_hashes.len()
            )));
        }


        let algorithm = if let Some(CommonMetadata::V00(cm)) = common_metadata {
            match cm.segment_hash_algorithm {
                0 => HashAlgorithm::Sha256,
                1 => HashAlgorithm::Sha384,
                2 => HashAlgorithm::Sha512,
                _ => HashAlgorithm::Sha256,
            }
        } else if let Some(CommonMetadata::V01(cm)) = common_metadata {
            match cm.base.segment_hash_algorithm {
                0 => HashAlgorithm::Sha256,
                1 => HashAlgorithm::Sha384,
                2 => HashAlgorithm::Sha512,
                _ => HashAlgorithm::Sha256,
            }
        } else {
            HashAlgorithm::Sha256
        };

        let expected_hash_size = algorithm.size();
        for (i, (comp, stored)) in computed.iter().zip(stored_hashes.iter()).enumerate() {
            if stored.len() != expected_hash_size {
                return Err(Error::HashVerification(format!(
                    "Stored hash[{}] has wrong size: {} (expected {})",
                    i,
                    stored.len(),
                    expected_hash_size
                )));
            }

            if comp.as_slice() != stored.as_slice() {
                return Err(Error::HashVerification(format!(
                    "Hash mismatch at segment {}: computed {} vs stored {}",
                    i,
                    hex::encode(comp),
                    hex::encode(stored)
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn size(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => SHA256_SIZE,
            HashAlgorithm::Sha384 => SHA384_SIZE,
            HashAlgorithm::Sha512 => SHA512_SIZE,
        }
    }
}

pub fn compute_hash(data: &[u8], algo: HashAlgorithm) -> Result<Vec<u8>> {
    match algo {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}