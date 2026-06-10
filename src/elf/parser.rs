use crate::elf::defines::{
    p_flags_os_page_mode, p_flags_os_segment_type, ELF_BLOCK_ALIGN,
    P_FLAGS_OS_ACCESS_TYPE_MASK, P_FLAGS_OS_ACCESS_TYPE_SHIFT, P_FLAGS_OS_SEGMENT_HASH,
    PF_OS_ACCESS_NOTUSED, PF_OS_ACCESS_SHARED, PF_OS_NON_PAGED_SEGMENT, PF_OS_PAGED_SEGMENT,
};
use crate::elf::header::ElfHeader;
use crate::elf::program_header::ProgramHeader;

#[derive(Debug)]
pub struct ElfParser {
    pub data: Vec<u8>,
    pub header: ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
}

impl ElfParser {
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let header = ElfHeader::from_bytes(data)?;
        let mut program_headers = Vec::with_capacity(header.e_phnum as usize);
        let phdr_size = header.e_phentsize as usize;

        for i in 0..header.e_phnum {
            let offset = (header.e_phoff + (i as u64) * (header.e_phentsize as u64)) as usize;
            if offset + phdr_size > data.len() {
                continue;
            }
            let phdr = ProgramHeader::from_bytes(&data[offset..offset + phdr_size], header.elf_class)?;
            program_headers.push(phdr);
        }

        Ok(ElfParser {
            data: data.to_vec(),
            header,
            program_headers,
        })
    }

    pub fn get_segment_data(&self, phdr: &ProgramHeader) -> &[u8] {
        let start = phdr.p_offset as usize;
        let end = start + phdr.p_filesz as usize;
        if end <= self.data.len() {
            &self.data[start..end]
        } else {
            &[]
        }
    }

    pub fn get_phdr_table_data(&self) -> &[u8] {
        let start = self.header.e_phoff as usize;
        let end = start + (self.header.e_phnum as usize * self.header.e_phentsize as usize);
        if end <= self.data.len() {
            &self.data[start..end]
        } else {
            &[]
        }
    }

    pub fn is_os_segment_hash(phdr: &ProgramHeader) -> bool {
        p_flags_os_segment_type(phdr.p_flags) == P_FLAGS_OS_SEGMENT_HASH
    }

    pub fn os_access_type(phdr: &ProgramHeader) -> u32 {
        (phdr.p_flags & P_FLAGS_OS_ACCESS_TYPE_MASK) >> P_FLAGS_OS_ACCESS_TYPE_SHIFT
    }

    pub fn is_hash_segment(phdr: &ProgramHeader) -> bool {
        Self::is_os_segment_hash(phdr)
    }

    pub fn find_hash_segment(&self) -> Option<&ProgramHeader> {
        self.program_headers.iter().find(|phdr| Self::is_os_segment_hash(phdr))
    }

    pub fn compute_segment_hashes(&self) -> Result<Vec<Vec<u8>>, &'static str> {
        use sha2::{Digest, Sha256};
        let mut hashes = Vec::new();

        for phdr in &self.program_headers {
            if Self::is_os_segment_hash(phdr) {
                continue;
            }

            let os_access = Self::os_access_type(phdr);
            if os_access == PF_OS_ACCESS_NOTUSED || os_access == PF_OS_ACCESS_SHARED {
                hashes.push(vec![0u8; 32]);
                continue;
            }

            if phdr.p_filesz == 0 {
                hashes.push(vec![0u8; 32]);
                continue;
            }

            let seg_data = self.get_segment_data(phdr);
            if seg_data.is_empty() {
                hashes.push(vec![0u8; 32]);
                continue;
            }

            let page_mode = p_flags_os_page_mode(phdr.p_flags);
            if page_mode == PF_OS_NON_PAGED_SEGMENT {
                let hash = Sha256::digest(seg_data).to_vec();
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
                    let hash = Sha256::digest(&page_data[..ELF_BLOCK_ALIGN as usize]).to_vec();
                    hashes.push(hash);
                    page_data = &page_data[ELF_BLOCK_ALIGN as usize..];
                }
            }
        }

        Ok(hashes)
    }
}
