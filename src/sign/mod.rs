#[cfg(feature = "sign")]
pub mod base_signer;
#[cfg(feature = "sign")]
pub mod test;
#[cfg(feature = "sign")]
pub mod local;
#[cfg(feature = "sign")]
pub mod plugin;

#[cfg(feature = "sign")]
pub use base_signer::Signer;

#[cfg(not(feature = "sign"))]
pub mod base_signer {
    pub trait Signer {
        fn sign(&self, _data: &[u8]) -> crate::error::Result<(Vec<u8>, Vec<Vec<u8>>)> {
            Err(crate::error::Error::Custom(
                "Signing not supported in this build".into(),
            ))
        }
    }
}

pub const ASSETS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/sign/assets");
