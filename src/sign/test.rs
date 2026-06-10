use crate::error::{Error, Result};
use crate::sign::base_signer::{default_subject, load_asset, Signer};
use crate::sign::local::LocalSigner;

pub struct TestSigner {
    local: LocalSigner,
    algo_dir: String,
}

impl TestSigner {
    pub fn new(
        algo: &str,
        hash: &str,
        key_size: Option<&str>,
        exponent: Option<u32>,
        curve: Option<&str>,
        padding: Option<&str>,
        root_cert_index: usize,
        chain_depth: u32,
    ) -> Result<Self> {
        let algo_dir =
            super::base_signer::algo_directory(algo, hash, key_size, exponent, curve, padding);

        let (root_cert, root_key_data) = load_asset(&algo_dir, "root", root_cert_index)?;

        let (ca_key_pem, ca_cert_pem) = if chain_depth >= 2 {
            let (cc, ck) = load_asset(&algo_dir, "ca", root_cert_index)?;
            (ck, cc)
        } else {
            (Vec::new(), Vec::new())
        };

        let local = match algo.to_lowercase().as_str() {
            "ecdsa" => LocalSigner::new_ecdsa(
                root_key_data, root_cert, ca_key_pem, ca_cert_pem,
                curve.unwrap_or("secp384r1"),
            )?,
            "rsa" => LocalSigner::new_rsa(
                root_key_data, root_cert, ca_key_pem, ca_cert_pem,
                hash, padding.unwrap_or("pkcs"),
            )?,
            _ => {
                return Err(Error::UnsupportedEncryptionScheme(format!(
                    "unknown algorithm: {}",
                    algo
                )))
            }
        };

        Ok(TestSigner { local, algo_dir })
    }
}

impl Signer for TestSigner {
    fn name(&self) -> &str {
        "test"
    }

    fn sign(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
        self.local.sign(data)
    }
}
