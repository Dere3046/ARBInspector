use crate::error::{Error, Result};

#[cfg(feature = "sign")]
pub fn generate_shared_secret(private_key_pem: &[u8], peer_public_der: &[u8]) -> Result<Vec<u8>> {
    use openssl::derive::Deriver;
    use openssl::pkey::PKey;

    let pkey = PKey::private_key_from_pem(private_key_pem)
        .map_err(|e| Error::Custom(format!("failed to load private key: {}", e)))?;

    let peer_pkey = PKey::public_key_from_der(peer_public_der)
        .map_err(|e| Error::Custom(format!("failed to load peer public key: {}", e)))?;

    let mut deriver = Deriver::new(&pkey)
        .map_err(|e| Error::Custom(format!("failed to create deriver: {}", e)))?;

    deriver.set_peer(&peer_pkey)
        .map_err(|e| Error::Custom(format!("failed to set peer key: {}", e)))?;

    deriver.derive_to_vec()
        .map_err(|e| Error::Custom(format!("ECDH key derivation failed: {}", e)))
}

#[cfg(not(feature = "sign"))]
pub fn generate_shared_secret(_private_key_pem: &[u8], _peer_public_der: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Custom("ECDH key exchange not supported (enable 'sign' feature)".into()))
}
