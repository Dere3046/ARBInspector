# arb_inspector_next

[中文版](README_zh.md)

A lightweight tool to extract Anti-Rollback (ARB) version from Qualcomm firmware images (ELF/MBN formats).

## Features

- Parse 32/64-bit ELF files with Qualcomm HASH segment
- Parse MBN files (v3/v5/v6/v7/v8)
- Extract ARB version from OEM metadata
- Support Hash Table Segment Header v3/v5/v6/v7/v8
- Support Metadata v0.0/v1.0/v2.0/v3.0/v3.1
- Support Common Metadata v0.0/v0.1
- Quick mode: output only ARB value
- Full mode: display detailed image information including:
  - ELF/MBN header information
  - Program headers with Qualcomm OS segment types
  - Hash Table Segment Header
  - Common Metadata
  - OEM Metadata (with ARB version)
  - Hash Table contents
- Compute and verify segment hashes

## Usage

```
arb_inspector_next [--debug] [--quick|--full] [-v] <image>
```

### Options

- `--debug` / `-d`: Enable verbose debug output
- `--quick` / `-q`: Output only ARB version (default mode)
- `--full` / `-f`: Output complete image information
- `--version` / `-v`: Show version and exit

### Examples

```bash
# Quick mode - output only ARB version
arb_inspector_next xbl_config.img

# Full mode - detailed analysis
arb_inspector_next --full xbl_config.img

# Debug mode - verbose output
arb_inspector_next --debug --full xbl_config.img
```

## Build

```bash
cargo build --release
```

The binary will be available at `target/release/arb_inspector` (or `arb_inspector.exe` on Windows).

## Output Format

### Quick Mode
Outputs only the ARB version number:
```
0
```

### Full Mode
Outputs detailed information:
```
File: xbl_config.img
Format: ELF (64-bit)
Entry point: 0x1494e000
Machine: 0x1
Type: 0x2
Flags: 0x5
Program headers: 8

Program Headers:
  [0] Type: NULL Offset: 0x0 VAddr: 0x0 FileSize: 0x200 MemSize: 0x0
      Flags: 0x7000000 Perm: None OS_Type: PHDR OS_Access: RW Page_Mode: NON_PAGED
  ...

Hash Table Segment Header:
  Version: 7
  Common Metadata Size: 24 (bytes)
  QTI Metadata Size: 0 (bytes)
  OEM Metadata Size: 224 (bytes)
  Hash Table Size: 384 (bytes)
  ...

Common Metadata:
  Version: 0.0
  One-shot Hash Algorithm: 37
  Segment Hash Algorithm: 0

OEM Metadata:
  Version: 3.0
  Anti-Rollback Version: 0
  ...

Anti-Rollback Version: 0
```

## Supported Formats

### ELF Files
- 32-bit and 64-bit ELF
- Qualcomm OS segment types (AMSS, HASH, PHDR, etc.)
- Hash Table Segment with metadata

### MBN Files
- MBN v3, v5, v6, v7, v8
- Image header parsing

## Metadata Versions

### Common Metadata
- v0.0: Basic hash algorithm configuration
- v0.1: Added ZI segment hash algorithm support

### OEM Metadata
- v0.0: Basic ARB and platform binding
- v1.0: Added JTAG ID and OEM Product ID binding
- v2.0: Added lifecycle states and OEM root certificate hash
- v3.0: Added QTI lifecycle state
- v3.1: Added measurement register target

## License

MIT - See [LICENSE](LICENSE)
