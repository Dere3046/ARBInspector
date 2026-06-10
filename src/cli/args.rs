use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct GlobalArgs {
    pub debug: bool,
    pub fast: bool,
    pub verify: bool,
    pub file: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct SecureImageArgs {
    pub infile: Option<PathBuf>,
    pub outfile: Option<PathBuf>,
    pub image_id: Option<u32>,
    pub qti: bool,
    pub do_hash: bool,
    pub do_sign: bool,
    pub do_encrypt: bool,
    pub do_inspect: bool,
    pub do_validate: bool,
    pub do_compress: bool,
    pub segment_hash_algorithm: Option<u32>,
    pub anti_rollback: Option<u32>,
    pub oem_id: Option<u32>,
    pub oem_product_id: Option<u32>,
    pub serial_number: Option<u32>,
    pub signing_mode: Option<String>,
    pub signature_format: Option<String>,
    pub root_certificate: Option<PathBuf>,
    pub ca_certificate: Option<PathBuf>,
    pub root_key: Option<PathBuf>,
    pub ca_key: Option<PathBuf>,
    pub encryption_mode: Option<String>,
    pub encryption_format: Option<String>,
}
