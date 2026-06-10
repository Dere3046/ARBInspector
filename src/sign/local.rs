use std::path::Path;

use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer as OpensslSigner;
use openssl::x509::X509;

use crate::error::{Error, Result};
use crate::sign::base_signer::Signer;

pub struct LocalSigner {
    root_key_pem: Vec<u8>,
    root_cert_pem: Vec<u8>,
    ca_key_pem: Vec<u8>,
    ca_cert_pem: Vec<u8>,
    digest: MessageDigest,
    is_ecdsa: bool,
}

impl LocalSigner {
    pub fn new_ecdsa(
        root_key_pem: Vec<u8>,
        root_cert_pem: Vec<u8>,
        ca_key_pem: Vec<u8>,
        ca_cert_pem: Vec<u8>,
        curve: &str,
    ) -> Result<Self> {
        let digest = match curve {
            "secp256r1" => MessageDigest::sha256(),
            "secp384r1" => MessageDigest::sha384(),
            _ => MessageDigest::sha384(),
        };
        Ok(LocalSigner {
            root_key_pem,
            root_cert_pem,
            ca_key_pem,
            ca_cert_pem,
            digest,
            is_ecdsa: true,
        })
    }

    pub fn new_rsa(
        root_key_pem: Vec<u8>,
        root_cert_pem: Vec<u8>,
        ca_key_pem: Vec<u8>,
        ca_cert_pem: Vec<u8>,
        hash_algo: &str,
        _padding: &str,
    ) -> Result<Self> {
        let digest = match hash_algo {
            "sha256" => MessageDigest::sha256(),
            "sha384" => MessageDigest::sha384(),
            "sha512" => MessageDigest::sha512(),
            _ => MessageDigest::sha256(),
        };
        Ok(LocalSigner {
            root_key_pem,
            root_cert_pem,
            ca_key_pem,
            ca_cert_pem,
            digest,
            is_ecdsa: false,
        })
    }

    fn sign_data(&self, data: &[u8], key_data: &[u8]) -> Result<Vec<u8>> {
        let pkey = PKey::private_key_from_der(key_data)
            .or_else(|_| PKey::private_key_from_pem(key_data))
            .map_err(|e| Error::Custom(format!("failed to load private key (tried DER then PEM): {}", e)))?;

        let mut signer = OpensslSigner::new(self.digest, &pkey)
            .map_err(|e| Error::Custom(format!("failed to create signer: {}", e)))?;

        signer
            .update(data)
            .map_err(|e| Error::Custom(format!("signer update failed: {}", e)))?;

        signer
            .sign_to_vec()
            .map_err(|e| Error::Custom(format!("signing failed: {}", e)))
    }

    fn load_x509(data: &[u8]) -> Result<X509> {
        X509::from_der(data).or_else(|_| {
            X509::from_pem(data)
                .map_err(|e| Error::Custom(format!("invalid certificate (tried DER then PEM): {}", e)))
        })
    }

    fn cert_chain(&self) -> Result<Vec<Vec<u8>>> {
        let root = Self::load_x509(&self.root_cert_pem)?;
        let mut chain = vec![root.to_der().unwrap_or_default()];

        if !self.ca_cert_pem.is_empty() {
            let ca = Self::load_x509(&self.ca_cert_pem)?;
            chain.push(ca.to_der().unwrap_or_default());
        }

        Ok(chain)
    }
}

impl Signer for LocalSigner {
    fn name(&self) -> &str {
        "local"
    }

    fn sign(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
        let signing_key = if !self.ca_key_pem.is_empty() {
            &self.ca_key_pem
        } else {
            &self.root_key_pem
        };

        let signature = self.sign_data(data, signing_key)?;
        let chain = self.cert_chain()?;

        Ok((signature, chain))
    }
}
