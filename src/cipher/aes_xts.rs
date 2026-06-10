use crate::error::{Error, Result};

/// AES-XTS encryption stub.
///
/// OpenSSL does not directly support XTS mode in its public API for all versions
/// (XTS is a ciphertext-stealing mode primarily used for disk/storage encryption).
/// Use a dedicated implementation such as the `aes-xts` crate, or implement it
/// via two stacked AES block operations with XEX-style tweaking.
pub fn encrypt_aes_xts(_plaintext: &[u8], _key: &[u8], _tweak: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Custom(
        "AES-XTS encryption not supported via openssl. \
         OpenSSL does not expose XTS mode in its public EVP API on all platforms. \
         Use a dedicated implementation (e.g., the `aes-xts` crate on crates.io)."
            .into(),
    ))
}
