pub fn get_lsb(value: u64) -> u32 {
    if value == 0 {
        return 0;
    }
    value.trailing_zeros()
}

pub fn p_flags_value(flag: u32, mask: u32, shift: u32) -> u32 {
    (flag & mask) >> shift
}

pub fn read_le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}

pub fn read_le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

pub fn read_le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}
