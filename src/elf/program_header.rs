use crate::data::{read_le_u32, read_le_u64};
use crate::elf::defines::{ELFCLASS32, ELFCLASS64, ELF32_PHDR_SIZE, ELF64_PHDR_SIZE};

#[derive(Debug, Clone)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl ProgramHeader {
    pub fn from_bytes(data: &[u8], elf_class: u8) -> Result<Self, &'static str> {
        match elf_class {
            ELFCLASS32 => {
                if data.len() < ELF32_PHDR_SIZE {
                    return Err("Insufficient data for ELF32 program header");
                }
                Ok(ProgramHeader {
                    p_type: read_le_u32(data, 0),
                    p_flags: read_le_u32(data, 24),
                    p_offset: read_le_u32(data, 4) as u64,
                    p_vaddr: read_le_u32(data, 8) as u64,
                    p_paddr: read_le_u32(data, 12) as u64,
                    p_filesz: read_le_u32(data, 16) as u64,
                    p_memsz: read_le_u32(data, 20) as u64,
                    p_align: read_le_u32(data, 28) as u64,
                })
            }
            ELFCLASS64 => {
                if data.len() < ELF64_PHDR_SIZE {
                    return Err("Insufficient data for ELF64 program header");
                }
                Ok(ProgramHeader {
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
            _ => Err("Unsupported ELF class for program header"),
        }
    }
}
