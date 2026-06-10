use crate::error::{Error, Result};

#[cfg(feature = "sign")]
pub fn sign_rsa(data: &[u8], key_pem: &[u8], bits: u32) -> Result<Vec<u8>> {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;

    let rsa = Rsa::private_key_from_pem(key_pem)
        .map_err(|e| Error::Custom(format!("failed to load RSA private key: {}", e)))?;

    let pkey = PKey::from_rsa(rsa)
        .map_err(|e| Error::Custom(format!("failed to create PKey: {}", e)))?;

    let digest = match bits {
        2048 => MessageDigest::sha256(),
        3072 => MessageDigest::sha384(),
        4096 => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    };

    let mut signer = Signer::new(digest, &pkey)
        .map_err(|e| Error::Custom(format!("failed to create signer: {}", e)))?;

    signer.update(data)
        .map_err(|e| Error::Custom(format!("signer update failed: {}", e)))?;

    signer.sign_to_vec()
        .map_err(|e| Error::Custom(format!("RSA signing failed: {}", e)))
}

#[cfg(not(feature = "sign"))]
pub fn sign_rsa(_data: &[u8], _key_pem: &[u8], _bits: u32) -> Result<Vec<u8>> {
    Err(Error::Custom("RSA signing not supported (enable 'sign' feature)".into()))
}
