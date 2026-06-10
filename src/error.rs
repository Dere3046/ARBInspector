use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // --- I/O ---
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // --- ELF parsing ---
    #[error("ELF magic not found: expected 7f 45 4c 46, got {hex}")]
    ElfInvalidMagic { hex: String },

    #[error("Not a little-endian ELF file (EI_DATA={0}). Only LE is supported.")]
    ElfEndiannessMismatch(u8),

    #[error("Unsupported ELF class: {0}. Only ELFCLASS32(1) and ELFCLASS64(2) are supported.")]
    ElfClassUnsupported(u8),

    #[error("ELF parsing error: {0}")]
    ElfParse(String),

    #[error("ELF header too short: {len} bytes, need at least {need}")]
    ElfHeaderTruncated { len: usize, need: usize },

    #[error("Program header #{index} extends beyond file bounds: offset=0x{off:x}, filesz=0x{sz:x}, file_size=0x{file:x}")]
    ProgramHeaderOutOfBounds { index: usize, off: u64, sz: u64, file: u64 },

    // --- MBN parsing ---
    #[error("MBN parsing error: {0}")]
    MbnParse(String),

    #[error("MBN version {0} is not recognized. Supported versions: 3, 5, 6, 7, 8.")]
    MbnUnsupportedVersion(u32),

    // --- Hash segment ---
    #[error("Hash segment parse error: {0}")]
    HashSegmentParse(String),

    #[error("Hash segment at offset 0x{off:x} extends beyond file bounds (file_size=0x{file:x}, segment_end=0x{end:x})")]
    HashSegmentOutOfBounds { off: usize, file: usize, end: usize },

    #[error("Unsupported hash segment version: v{0}. This tool only supports versions 3, 5, 6, 7, 8.")]
    UnsupportedHashSegmentVersion(u32),

    #[error("Hash segment header plausibility check failed: version={v}, common_sz=0x{cm:x}, qti_sz=0x{qt:x}, oem_sz=0x{om:x}, hash_sz=0x{ht:x}")]
    HashSegmentHeaderImplausible { v: u32, cm: usize, qt: usize, om: usize, ht: usize },

    #[error("Hash segment found but hash table is empty (size=0). Image may use per-page hashing or one-shot hash.")]
    EmptyHashTable,

    #[error("Image contains one-shot hash segment (PT_ONE_SHOT_HASH). This tool only supports per-segment hash verification.")]
    OneShotHashNotSupported,

    // --- Metadata ---
    #[error("Metadata parse error: {0}")]
    MetadataParse(String),

    #[error("Metadata too short: {len} bytes, need at least {need} for version {major}.{minor}")]
    MetadataTruncated { major: u32, minor: u32, len: usize, need: usize },

    #[error("Unsupported metadata version: {major}.{minor}. Cannot parse OEM/QTI metadata.")]
    UnsupportedMetadataVersion { major: u32, minor: u32 },

    #[error("Unsupported common metadata version: {major}.{minor}. Cannot determine hash algorithm.")]
    UnsupportedCommonMetadataVersion { major: u32, minor: u32 },

    // --- Encryption ---
    #[error("Encryption parameter parse error: {0}")]
    EncryptionParamParse(String),

    #[error("Unsupported encryption scheme: {0}. This tool only parses/detects encryption parameters, it cannot decrypt.")]
    UnsupportedEncryptionScheme(String),

    #[error("Unknown encryption parameter type: magic={magic_hex}, version={version}. Expected QBEC ('CEBQ') or UIE ('ISMQ').")]
    UnknownEncryptionType { magic_hex: String, version: u32 },

    #[error("Encrypted image detected ({scheme}), but cannot decrypt without Qualcomm key infrastructure. ARB extraction may be from unencrypted metadata.")]
    EncryptedImageNoDecrypt { scheme: String },

    #[error("Image uses Sign-then-Encrypt ordering with QBEC v2. Encryption parameters are present but metadata may be intact.")]
    SignThenEncryptDetected,

    // --- Verification ---
    #[error("Hash verification failed: {0}")]
    HashVerification(String),

    #[error("Computed {computed} segment hashes but stored {stored}. Hash count mismatch.")]
    HashCountMismatch { computed: usize, stored: usize },

    #[error("Hash algorithm mismatch: common metadata specifies algorithm id {algo_id}, but stored hash size ({hash_size}) does not match")]
    HashAlgorithmMismatch { algo_id: u32, hash_size: usize },

    // --- Tool usage ---
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Unsupported file format")]
    UnsupportedFormat,

    // --- Catch-all ---
    #[error("{0}")]
    Custom(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Error::Custom(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Custom(s)
    }
}
