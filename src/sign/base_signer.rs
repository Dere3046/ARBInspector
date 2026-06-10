use std::path::PathBuf;

use crate::error::{Error, Result};

pub trait Signer {
    fn name(&self) -> &str;
    fn sign(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)>;
}

pub fn default_subject() -> String {
    "/C=US/ST=California/CN=SecTools Test User/O=SecTools/L=San Diego".into()
}

pub fn hash_data_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

pub fn hash_data_sha384(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha384};
    Sha384::digest(data).to_vec()
}

pub fn algo_directory(
    algo: &str,
    hash: &str,
    key_size: Option<&str>,
    exponent: Option<u32>,
    curve: Option<&str>,
    padding: Option<&str>,
) -> String {
    let mut dir = algo.to_lowercase();
    match algo.to_lowercase().as_str() {
        "ecdsa" => {
            dir.push('_');
            dir.push_str(&hash.to_lowercase());
            dir.push('_');
            dir.push_str(curve.unwrap_or("secp384r1"));
        }
        "rsa" => {
            dir.push('_');
            dir.push_str(key_size.unwrap_or("4096"));
            dir.push('_');
            dir.push_str(&exponent.unwrap_or(65537).to_string());
            dir.push('_');
            dir.push_str(&hash.to_lowercase());
            dir.push('_');
            dir.push_str(padding.unwrap_or("pkcs"));
        }
        _ => {}
    }
    dir
}

pub fn assets_path(algo: &str, asset: &str, index: usize, ext: &str) -> PathBuf {
    let base: PathBuf = crate::sign::ASSETS_DIR.into();
    base.join(algo).join(format!("{}{}.{}", asset, index, ext))
}

pub fn load_asset(algo: &str, asset: &str, index: usize) -> Result<(Vec<u8>, Vec<u8>)> {
    let cer = std::fs::read(assets_path(algo, asset, index, "cer")).map_err(|e| {
        Error::Custom(format!("Cannot load cert {}{} in {}: {}", asset, index, algo, e))
    })?;
    let key = std::fs::read(assets_path(algo, asset, index, "key")).map_err(|e| {
        Error::Custom(format!("Cannot load key {}{} in {}: {}", asset, index, algo, e))
    })?;
    Ok((cer, key))
}
