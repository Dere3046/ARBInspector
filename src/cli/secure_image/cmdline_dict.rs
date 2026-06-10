/// Maps to Qualcomm's cmdline_dict.py argument groupings.
/// Each feature-gated function returns the list of arguments for that group.
/// When the feature is disabled, args show "not supported in this build".

pub struct ArgDef {
    pub names: &'static [&'static str],
    pub help: &'static str,
    pub supported: bool,
}

macro_rules! arg {
    ($($name:expr),+ => $help:expr) => {
        ArgDef {
            names: &[$($name),+],
            help: $help,
            supported: true,
        }
    };
    ($($name:expr),+ => $help:expr, disabled) => {
        ArgDef {
            names: &[$($name),+],
            help: $help,
            supported: false,
        }
    };
}

pub const IMAGE_INPUTS: &[ArgDef] = &[
    arg!("infile" => "Input image file path"),
    arg!("--image-id" => "Image ID (e.g. 0x10 for XBL)"),
];

pub const IMAGE_OUTPUTS: &[ArgDef] = &[
    arg!("--outfile" => "Output image file path"),
];

pub const AUTHORITY: &[ArgDef] = &[
    arg!("--qti" => "Operate as QTI authority (default: OEM)"),
];

pub const DEVICE_RESTRICTIONS: &[ArgDef] = &[
    arg!("--anti-rollback-version", "-a" => "Anti-rollback version"),
    arg!("--oem-id" => "OEM ID"),
    arg!("--oem-product-id" => "OEM product ID"),
    arg!("--serial-number" => "Serial number"),
];

#[cfg(feature = "hash-gen")]
pub const HASH_OP: &[ArgDef] = &[
    arg!("--hash" => "Add or replace hash table segment"),
    arg!("--segment-hash-algorithm" => "Hash algorithm (0=sha256, 1=sha384, 2=sha512)"),
];

#[cfg(not(feature = "hash-gen"))]
pub const HASH_OP: &[ArgDef] = &[
    arg!("--hash" => "Hash generation not supported in this build", disabled),
];

#[cfg(feature = "sign")]
pub const SIGN_OP: &[ArgDef] = &[
    arg!("--sign" => "Sign the image"),
    arg!("--signing-mode" => "Signing mode: local | test"),
    arg!("--signature-format" => "Signature format (e.g. rsa2048, ecdsa-p384)"),
    arg!("--root-certificate" => "Root certificate file (PEM)"),
    arg!("--root-key" => "Root private key file (PEM)"),
    arg!("--ca-certificate" => "CA certificate file (PEM)"),
    arg!("--ca-key" => "CA private key file (PEM)"),
];

#[cfg(not(feature = "sign"))]
pub const SIGN_OP: &[ArgDef] = &[
    arg!("--sign" => "Image signing not supported in this build", disabled),
];

#[cfg(feature = "encrypt")]
pub const ENCRYPT_OP: &[ArgDef] = &[
    arg!("--encrypt" => "Encrypt the image"),
    arg!("--encryption-mode" => "Encryption mode: local | test"),
    arg!("--encryption-format" => "Encryption format: qbec | uie"),
];

#[cfg(not(feature = "encrypt"))]
pub const ENCRYPT_OP: &[ArgDef] = &[
    arg!("--encrypt" => "Image encryption not supported in this build", disabled),
];

#[cfg(feature = "validate")]
pub const VALIDATE_OP: &[ArgDef] = &[
    arg!("--validate" => "Validate image against security profile"),
];

#[cfg(not(feature = "validate"))]
pub const VALIDATE_OP: &[ArgDef] = &[
    arg!("--validate" => "Image validation not supported in this build", disabled),
];

#[cfg(feature = "compress")]
pub const COMPRESS_OP: &[ArgDef] = &[
    arg!("--compress" => "Compress output image (LZMA)"),
];

#[cfg(not(feature = "compress"))]
pub const COMPRESS_OP: &[ArgDef] = &[
    arg!("--compress" => "Image compression not supported in this build", disabled),
];

pub fn print_help() {
    println!("arb_inspector_next v{}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage: arb_inspector [--debug] [--fast] <file>");
    println!("       arb_inspector secure-image [options]");
    println!();
    println!("Subcommands:");
    println!("  (no subcommand)    Inspect image and extract ARB");
    println!("  secure-image       Generate secure Qualcomm images (hash/sign/encrypt)");
    println!();
    println!("Secure Image Options:");
    println!();
    for group in &[IMAGE_INPUTS, IMAGE_OUTPUTS, AUTHORITY, DEVICE_RESTRICTIONS,
                    HASH_OP, SIGN_OP, ENCRYPT_OP, VALIDATE_OP, COMPRESS_OP]
    {
        for arg in *group {
            let status = if arg.supported { "" } else { " [disabled in this build]" };
            let names = arg.names.join(", ");
            println!("  {:<30} {}{}", names, arg.help, status);
        }
        println!();
    }
}
