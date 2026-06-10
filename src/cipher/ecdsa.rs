use crate::error::{Error, Result};

#[cfg(feature = "sign")]
pub fn sign_ecdsa_p384(data: &[u8], key_pem: &[u8]) -> Result<Vec<u8>> {
    use openssl::ec::EcKey;
    use openssl::ecdsa::EcdsaSig;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;

    let ec_key = EcKey::private_key_from_pem(key_pem)
        .map_err(|e| Error::Custom(format!("failed to load EC private key: {}", e)))?;

    let curve = ec_key.group().curve_name()
        .ok_or_else(|| Error::Custom("unknown EC curve".into()))?;
    if curve != Nid::SECP384R1 {
        return Err(Error::Custom(format!("expected P-384 curve, got {:?}", curve)));
    }

    let digest = openssl::hash::hash(MessageDigest::sha384(), data)
        .map_err(|e| Error::Custom(format!("SHA-384 hash failed: {}", e)))?;

    let sig = EcdsaSig::sign(&digest, &ec_key)
        .map_err(|e| Error::Custom(format!("ECDSA signing failed: {}", e)))?;

    sig.to_der()
        .map_err(|e| Error::Custom(format!("DER encoding of signature failed: {}", e)))
}

#[cfg(not(feature = "sign"))]
pub fn sign_ecdsa_p384(_data: &[u8], _key_pem: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Custom("ECDSA signing not supported (enable 'sign' feature)".into()))
}

#[cfg(feature = "sign")]
pub fn verify_ecdsa_p384(data: &[u8], signature: &[u8], cert_pem: &[u8]) -> Result<bool> {
    use openssl::ec::EcKey;
    use openssl::ecdsa::EcdsaSig;
    use openssl::hash::MessageDigest;
    use openssl::x509::X509;

    let cert = X509::from_pem(cert_pem)
        .map_err(|e| Error::Custom(format!("failed to load certificate: {}", e)))?;

    let pkey = cert.public_key()
        .map_err(|e| Error::Custom(format!("failed to extract public key: {}", e)))?;

    let ec_key = pkey.ec_key()
        .map_err(|e| Error::Custom(format!("not an EC key: {}", e)))?;

    let digest = openssl::hash::hash(MessageDigest::sha384(), data)
        .map_err(|e| Error::Custom(format!("SHA-384 hash failed: {}", e)))?;

    let sig = EcdsaSig::from_der(signature)
        .map_err(|e| Error::Custom(format!("failed to parse DER signature: {}", e)))?;

    sig.verify(&digest, &ec_key)
        .map_err(|e| Error::Custom(format!("ECDSA verification failed: {}", e)))
}

#[cfg(not(feature = "sign"))]
pub fn verify_ecdsa_p384(_data: &[u8], _signature: &[u8], _cert_pem: &[u8]) -> Result<bool> {
    Err(Error::Custom("ECDSA verification not supported (enable 'sign' feature)".into()))
}
