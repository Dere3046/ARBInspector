use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ELF parsing error: {0}")]
    ElfParse(&'static str),

    #[error("MBN parsing error: {0}")]
    MbnParse(&'static str),

    #[error("Metadata parsing error: {0}")]
    MetadataParse(&'static str),

    #[error("Hash verification failed: {0}")]
    HashVerification(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Unsupported file format")]
    UnsupportedFormat,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Error::ElfParse(s)
    }
}