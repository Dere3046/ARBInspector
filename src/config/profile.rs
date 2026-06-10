use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub enum ImageFormat {
    Elf,
    ElfWithHash,
    Mbn,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Authority {
    Oem,
    Qti,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SigningMode {
    Local,
    Test,
    Plugin,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionMode {
    Local,
    Test,
    Plugin,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionType {
    None,
    Qbec,
    Uie,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionOrder {
    EncryptThenSign,
    SignThenEncrypt,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn digest_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    pub fn from_id(id: u32) -> Self {
        match id {
            1 => HashAlgorithm::Sha384,
            2 => HashAlgorithm::Sha512,
            _ => HashAlgorithm::Sha256,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityProfile {
    pub authority: Authority,
    pub image_format: ImageFormat,
    pub hash_algorithm: HashAlgorithm,
    pub sign: Option<SignConfig>,
    pub encrypt: Option<EncryptConfig>,
}

#[derive(Debug, Clone)]
pub struct SignConfig {
    pub mode: SigningMode,
    pub signature_format: String,
    pub cert_chain_depth: u32,
    pub root_cert_count: u32,
    pub pad_for_hybrid_sign: bool,
}

#[derive(Debug, Clone)]
pub struct EncryptConfig {
    pub mode: EncryptionMode,
    pub etype: EncryptionType,
    pub order: EncryptionOrder,
}

impl Default for SecurityProfile {
    fn default() -> Self {
        SecurityProfile {
            authority: Authority::Oem,
            image_format: ImageFormat::ElfWithHash,
            hash_algorithm: HashAlgorithm::Sha256,
            sign: None,
            encrypt: None,
        }
    }
}

impl SecurityProfile {
    pub fn builder() -> ProfileBuilder {
        ProfileBuilder::new()
    }

    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

pub struct ProfileBuilder {
    profile: SecurityProfile,
}

impl ProfileBuilder {
    pub fn new() -> Self {
        ProfileBuilder {
            profile: SecurityProfile::default(),
        }
    }

    pub fn authority(mut self, a: Authority) -> Self {
        self.profile.authority = a;
        self
    }

    pub fn hash_algorithm(mut self, a: HashAlgorithm) -> Self {
        self.profile.hash_algorithm = a;
        self
    }

    pub fn sign_config(mut self, cfg: SignConfig) -> Self {
        self.profile.sign = Some(cfg);
        self
    }

    pub fn encrypt_config(mut self, cfg: EncryptConfig) -> Self {
        self.profile.encrypt = Some(cfg);
        self
    }

    pub fn build(self) -> SecurityProfile {
        self.profile
    }
}
