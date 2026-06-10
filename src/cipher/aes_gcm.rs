use crate::error::{Error, Result};

#[cfg(feature = "sign")]
pub fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    use openssl::symm::{Cipher, Crypter, Mode};

    if key.len() != 32 {
        return Err(Error::Custom("AES-256-GCM key must be exactly 32 bytes".into()));
    }

    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce))
        .map_err(|e| Error::Custom(format!("failed to create crypter: {}", e)))?;

    let mut out = vec![0u8; plaintext.len() + 16];
    let count = crypter.update(plaintext, &mut out)
        .map_err(|e| Error::Custom(format!("encrypt update failed: {}", e)))?;

    let rest = crypter.finalize(&mut out[count..])
        .map_err(|e| Error::Custom(format!("encrypt finalize failed: {}", e)))?;

    out.truncate(count + rest);

    let mut tag = vec![0u8; 16];
    crypter.get_tag(&mut tag)
        .map_err(|e| Error::Custom(format!("failed to get GCM tag: {}", e)))?;

    out.extend_from_slice(&tag);
    Ok(out)
}

#[cfg(not(feature = "sign"))]
pub fn encrypt_aes_gcm(_plaintext: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Custom("AES-GCM encryption not supported (enable 'sign' feature)".into()))
}
