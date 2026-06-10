# arb_inspector

[中文版](README_zh.md)

Inspect and generate Qualcomm secure ELF/MBN images.

## Features

- Parse 32/64-bit ELF with Qualcomm HASH segment
- Parse MBN v3/v5/v6/v7/v8
- Extract Anti-Rollback version from OEM metadata
- Detect QTI/OEM signatures and encryption params
- Generate hash segments, sign (ECDSA/RSA), encrypt params
- LZMA/XZ compression and PIL split
- All features are compile-time gated for minimal builds

## Usage

```
arb_inspector [--fast] [--debug] [--verify] <image>
arb_inspector secure-image [options]
```

No flags = full display (default).
`--fast` = only ARB value.
`--debug` = step by step trace.

### secure-image

```
--infile <path>  --outfile <path>
--hash           generate hash table segment
--sign           sign image (local|test|plugin)
--encrypt        add encryption params (qbec|uie)
--inspect        print image details
--validate       validate against profile
--compress       LZMA compress output
--pil-split      split into .mdt + .bXX
```

### Build notes

```
cargo build --release                          # full
cargo build --no-default-features              # inspect only
cargo build --features sign                    # +signing
cargo build --features "sign encrypt"          # +encryption
```

## Example

```bash
# Quick ARB
arb_inspector --fast xbl_a

# Full inspect
arb_inspector abl_a

# Generate hash segment with updated ARB
arb_inspector secure-image --infile abl_a --outfile abl_new.elf --hash --anti-rollback-version 5

# Hash + sign with built-in ECDSA test certs
arb_inspector secure-image --infile abl_a --outfile abl_signed.elf --hash --sign --signing-mode test
```

### Output

```
File: xbl_a
Format: ELF (64-bit)
Machine: 0xb7
Program headers: 9

Hash Table Segment Header:
  Version: 7
  Common Metadata Size: 24 (bytes)
  OEM Metadata Size: 224 (bytes)
  Hash Table Size: 432 (bytes)
  QTI Signature Size: 104 (bytes)
  OEM Signature Size: 104 (bytes)

Signed: Yes (QTI + OEM)

Common Metadata:
  Version: 0.0
  Software ID: 0x36
  Hash Table Algorithm: SHA384 (3)

OEM Metadata:
  Version: 3.0
  Anti-Rollback Version: 0
  OEM ID: 0x51

Anti-Rollback Version: 0
```

## Metadata formats

Common metadata V0.0: 24B
  major, minor, software_id, secondary_sw_id, hash_table_algo, mrc_target

OEM metadata V2.0/V3.0: 224B
  12 soc_hw_vers, product_segment_id, jtag_id, 8 serial u64,
  oem_id, oem_product_id, lifecycle states, oem_rch_hash, flags

OEM metadata V0.0/V1.0: 120B (legacy v6 format)

## License

MIT
