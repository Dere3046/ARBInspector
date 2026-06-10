use crate::data::{read_le_u16, read_le_u32, read_le_u64};
use crate::elf::defines::{ELFCLASS32, ELFCLASS64, ELFCLASSNONE, ELF32_HDR_SIZE, ELF64_HDR_SIZE, ELFMAG};

#[derive(Debug, Clone)]
pub struct ElfHeader {
    pub elf_class: u8,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl ElfHeader {
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 || &data[0..4] != ELFMAG {
            return Err("Invalid ELF magic");
        }
        let elf_class = data[4];
        if data.len() < 52 {
            return Err("Insufficient data for ELF header");
        }
        match elf_class {
            ELFCLASS32 => {
                if data.len() < ELF32_HDR_SIZE {
                    return Err("Insufficient data for ELF32 header");
                }
                Ok(ElfHeader {
                    elf_class: ELFCLASS32,
                    e_type: read_le_u16(data, 16),
                    e_machine: read_le_u16(data, 18),
                    e_entry: read_le_u32(data, 24) as u64,
                    e_phoff: read_le_u32(data, 28) as u64,
                    e_shoff: read_le_u32(data, 32) as u64,
                    e_flags: read_le_u32(data, 36),
                    e_ehsize: read_le_u16(data, 40),
                    e_phentsize: read_le_u16(data, 42),
                    e_phnum: read_le_u16(data, 44),
                    e_shentsize: read_le_u16(data, 46),
                    e_shnum: read_le_u16(data, 48),
                    e_shstrndx: read_le_u16(data, 50),
                })
            }
            ELFCLASS64 => {
                if data.len() < ELF64_HDR_SIZE {
                    return Err("Insufficient data for ELF64 header");
                }
                Ok(ElfHeader {
                    elf_class: ELFCLASS64,
                    e_type: read_le_u16(data, 16),
                    e_machine: read_le_u16(data, 18),
                    e_entry: read_le_u64(data, 24),
                    e_phoff: read_le_u64(data, 32),
                    e_shoff: read_le_u64(data, 40),
                    e_flags: read_le_u32(data, 48),
                    e_ehsize: read_le_u16(data, 52),
                    e_phentsize: read_le_u16(data, 54),
                    e_phnum: read_le_u16(data, 56),
                    e_shentsize: read_le_u16(data, 58),
                    e_shnum: read_le_u16(data, 60),
                    e_shstrndx: read_le_u16(data, 62),
                })
            }
            ELFCLASSNONE => Err("Unsupported ELF class: none"),
            _ => Err("Unknown ELF class"),
        }
    }

    pub fn is_32bit(&self) -> bool {
        self.elf_class == ELFCLASS32
    }

    pub fn is_64bit(&self) -> bool {
        self.elf_class == ELFCLASS64
    }

    pub fn phdr_table_end(&self) -> u64 {
        self.e_phoff + (self.e_phnum as u64) * (self.e_phentsize as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_elf32() -> Vec<u8> {
        let seg_data = b"TEST_DATA";
        let phdr_count: u16 = 1;
        let ehdr_size: u16 = 52;
        let phdr_size: u16 = 32;
        let phoff: u32 = ehdr_size as u32;
        let data_off: u32 = phoff + phdr_count as u32 * phdr_size as u32;
        let filesz: u32 = seg_data.len() as u32;

        let mut d: Vec<u8> = Vec::new();
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
    fn test_elf32_header_parse() {
        let d = make_elf32();
        let h = ElfHeader::from_bytes(&d).unwrap();
        assert!(h.is_32bit());
        assert_eq!(h.e_type, 2);
        assert_eq!(h.e_machine, 40);
        assert_eq!(h.e_phnum, 1);
        assert_eq!(h.e_phoff, 52);
    }

    #[test]
    fn test_elf64_header_parse() {
        let phdr_count: u16 = 1;
        let ehdr_size: u16 = 64;
        let phdr_size: u16 = 56;
        let phoff: u64 = ehdr_size as u64;
        let data_off: u64 = phoff + phdr_count as u64 * phdr_size as u64;

        let mut d: Vec<u8> = Vec::new();
        d.extend_from_slice(b"\x7fELF");
        d.push(2); d.push(1); d.push(1); d.push(0);
        d.extend_from_slice(&[0u8; 8]);
        d.extend_from_slice(&2u16.to_le_bytes());
        d.extend_from_slice(&183u16.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
        d.extend_from_slice(&phoff.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&ehdr_size.to_le_bytes());
        d.extend_from_slice(&phdr_size.to_le_bytes());
        d.extend_from_slice(&phdr_count.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&7u32.to_le_bytes());
        d.extend_from_slice(&data_off.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
        d.extend_from_slice(&16u64.to_le_bytes());
        d.extend_from_slice(&16u64.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
        d.extend_from_slice(b"TEST_DATA");
        let h = ElfHeader::from_bytes(&d).unwrap();
        assert!(h.is_64bit());
        assert_eq!(h.e_machine, 183);
        assert_eq!(h.e_phnum, 1);
        assert_eq!(h.e_phoff, 64);
    }
}
