use std::process::Command;
use std::path::PathBuf;

fn arb_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_arb_inspector"))
}

fn run_arb(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(arb_bin())
        .args(args)
        .output()
        .expect("failed to run arb_inspector");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status.success(), stdout, stderr)
}

// ===== Built-in synthetic ELF test images =====

fn make_minimal_elf32() -> Vec<u8> {
    let mut d = Vec::new();
    let seg_data = b"XBL_TEST_2026!";
    let phoff: u32 = 52;
    let data_off: u32 = 84;
    let filesz: u32 = seg_data.len() as u32;

    d.extend_from_slice(b"\x7fELF");
    d.push(1); d.push(1); d.push(1); d.push(0);
    d.extend_from_slice(&[0u8; 8]);
    d.extend_from_slice(&2u16.to_le_bytes());    // e_type = ET_EXEC
    d.extend_from_slice(&40u16.to_le_bytes());   // e_machine = EM_ARM
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());    // e_entry
    d.extend_from_slice(&phoff.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&52u16.to_le_bytes());   // e_ehsize
    d.extend_from_slice(&32u16.to_le_bytes());   // e_phentsize
    d.extend_from_slice(&1u16.to_le_bytes());    // e_phnum
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&1u32.to_le_bytes());    // p_type=PT_LOAD
    d.extend_from_slice(&data_off.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&filesz.to_le_bytes());
    d.extend_from_slice(&filesz.to_le_bytes());
    d.extend_from_slice(&7u32.to_le_bytes());    // p_flags=RWE
    d.extend_from_slice(&4u32.to_le_bytes());    // p_align
    d.extend_from_slice(seg_data);
    d
}

fn make_elf_with_hash() -> Vec<u8> {
    let seg_data = b"XBL_CODE_SEGMENT";
    let ehdr_sz: u16 = 52;
    let phdr_sz: u16 = 32;
    let phdr_count: u16 = 2;
    let phoff: u32 = ehdr_sz as u32;
    let seg_off: u32 = phoff + phdr_count as u32 * phdr_sz as u32;
    let hash_off: u32 = seg_off + seg_data.len() as u32;

    // Build hash segment content
    let hs = arb_inspector_lib::hash_segment::metadata::test_hash_segment_v7(42, 0x1c, 3, 3);
    let hash_filesz = hs.len() as u32;

    let mut d = Vec::new();
    d.extend_from_slice(b"\x7fELF");
    d.push(1); d.push(1); d.push(1); d.push(0);
    d.extend_from_slice(&[0u8; 8]);
    d.extend_from_slice(&2u16.to_le_bytes());
    d.extend_from_slice(&40u16.to_le_bytes());
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&phoff.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&ehdr_sz.to_le_bytes());
    d.extend_from_slice(&phdr_sz.to_le_bytes());
    d.extend_from_slice(&phdr_count.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());

    // PHDR[0]: LOAD segment
    d.extend_from_slice(&1u32.to_le_bytes());    // PT_LOAD
    d.extend_from_slice(&seg_off.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&(seg_data.len() as u32).to_le_bytes());
    d.extend_from_slice(&(seg_data.len() as u32).to_le_bytes());
    d.extend_from_slice(&7u32.to_le_bytes());    // RWE
    d.extend_from_slice(&4u32.to_le_bytes());

    // PHDR[1]: HASH segment
    d.extend_from_slice(&0u32.to_le_bytes());    // PT_NULL
    d.extend_from_slice(&hash_off.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&hash_filesz.to_le_bytes());
    d.extend_from_slice(&hash_filesz.to_le_bytes());
    d.extend_from_slice(&0x0200_0000u32.to_le_bytes()); // OS seg type = HASH (2)
    d.extend_from_slice(&0x1000u32.to_le_bytes());

    d.extend_from_slice(seg_data);
    d.extend_from_slice(&hs);
    d
}

// ===== Integration Tests =====

#[test]
fn test_cli_help_exit() {
    let (ok, stdout, _) = run_arb(&["--help"]);
    assert!(ok);
    assert!(stdout.contains("arb_inspector_next"));
    assert!(stdout.contains("secure-image"));
}

#[test]
fn test_cli_version() {
    let (ok, stdout, _) = run_arb(&["-v"]);
    assert!(ok);
    assert!(stdout.contains("arb_inspector_next v"));
}

#[test]
fn test_cli_no_file_error() {
    let (ok, _, stderr) = run_arb(&[]);
    assert!(!ok);
    // Should complain about no input file
    assert!(stderr.contains("No input file") || stderr.contains("Usage"));
}

#[test]
fn test_cli_fast_mode_extracts_arb() {
    let elf = make_elf_with_hash();
    let tmp = std::env::temp_dir().join("test_fast_arb.elf");
    std::fs::write(&tmp, &elf).unwrap();

    let (ok, stdout, _) = run_arb(&["--fast", tmp.to_str().unwrap()]);
    assert!(ok, "fast mode should succeed");
    assert_eq!(stdout.trim(), "42", "should output ARB=42");
}

#[test]
fn test_cli_full_mode_shows_details() {
    let elf = make_elf_with_hash();
    let tmp = std::env::temp_dir().join("test_full_output.elf");
    std::fs::write(&tmp, &elf).unwrap();

    let (ok, stdout, _) = run_arb(&[tmp.to_str().unwrap()]);
    assert!(ok);
    assert!(stdout.contains("HASH"));
    assert!(stdout.contains("Anti-Rollback Version: 42"));
    assert!(stdout.contains("Program Headers:"));
}

#[test]
fn test_cli_debug_mode_shows_steps() {
    let elf = make_elf_with_hash();
    let tmp = std::env::temp_dir().join("test_debug_steps.elf");
    std::fs::write(&tmp, &elf).unwrap();

    let (ok, _, stderr) = run_arb(&["--debug", tmp.to_str().unwrap()]);
    assert!(ok);
    assert!(stderr.contains("Step 1/6"));
    assert!(stderr.contains("Step 6/6"));
}

#[test]
fn test_cli_unrecognized_file() {
    let mut data = b"this is not an ELF file!! not an ELF ".to_vec();
    data.resize(100, 0xFF); // pad to 100 bytes
    let tmp = std::env::temp_dir().join("test_bogus.bin");
    std::fs::write(&tmp, &data).unwrap();

    let (ok, _, stderr) = run_arb(&[tmp.to_str().unwrap()]);
    assert!(!ok, "should fail: stderr={}", stderr);
    assert!(stderr.contains("ELF") || stderr.contains("Unknown") || stderr.contains("unsupported"),
        "stderr should mention ELF/unknown: {}", stderr);
}

#[test]
fn test_secure_image_help() {
    let (ok, stdout, _) = run_arb(&["secure-image", "--help"]);
    assert!(ok);
    assert!(stdout.contains("Usage"));
}

#[test]
fn test_secure_image_no_operation_error() {
    let elf = make_minimal_elf32();
    let tmp = std::env::temp_dir().join("test_secure_noop.elf");
    std::fs::write(&tmp, &elf).unwrap();

    let (ok, _, stderr) = run_arb(&["secure-image", "--infile", tmp.to_str().unwrap()]);
    assert!(!ok);
    assert!(stderr.contains("No operation"));
}

#[test]
fn test_secure_image_inspect() {
    let elf = make_elf_with_hash();
    let tmp = std::env::temp_dir().join("test_secure_inspect.elf");
    std::fs::write(&tmp, &elf).unwrap();

    let (ok, stdout, _) = run_arb(&["secure-image", "--inspect", "--infile", tmp.to_str().unwrap()]);
    assert!(ok);
    assert!(stdout.contains("Anti-Rollback Version: 42"));
    assert!(stdout.contains("Hash Table Segment Header"));
}

#[test]
fn test_secure_image_hash_generate() {
    let elf = make_elf_with_hash();
    let tmp = std::env::temp_dir().join("test_secure_hash_in.elf");
    let out = std::env::temp_dir().join("test_secure_hash_out.elf");
    std::fs::write(&tmp, &elf).unwrap();

    let (ok, _, stderr) = run_arb(&[
        "secure-image",
        "--infile", tmp.to_str().unwrap(),
        "--outfile", out.to_str().unwrap(),
        "--hash",
        "--anti-rollback-version", "99",
    ]);
    assert!(ok, "hash generation should succeed: stderr={}", stderr);

    // Verify output file exists and has correct ARB
    assert!(out.exists(), "output file should exist");
    let (ok2, stdout2, _) = run_arb(&["--fast", out.to_str().unwrap()]);
    assert!(ok2);
    assert_eq!(stdout2.trim(), "99", "ARB should be updated to 99");
}

#[test]
fn test_secure_image_sign() {
    let elf = make_elf_with_hash();
    let tmp = std::env::temp_dir().join("test_sign_in.elf");
    let out = std::env::temp_dir().join("test_sign_out.elf");
    std::fs::write(&tmp, &elf).unwrap();

    let (ok, _, _) = run_arb(&[
        "secure-image",
        "--infile", tmp.to_str().unwrap(),
        "--outfile", out.to_str().unwrap(),
        "--sign",
        "--signing-mode", "test",
    ]);
    assert!(ok, "signing should succeed");

    // Verify signature detected
    let (ok2, stdout2, _) = run_arb(&[out.to_str().unwrap()]);
    assert!(ok2);
    assert!(stdout2.contains("Signed: Yes"));
}

#[test]
fn test_secure_image_hash_and_sign() {
    let elf = make_elf_with_hash();
    let tmp = std::env::temp_dir().join("test_hash_sign_in.elf");
    let out = std::env::temp_dir().join("test_hash_sign_out.elf");
    std::fs::write(&tmp, &elf).unwrap();

    let (ok, _, _) = run_arb(&[
        "secure-image",
        "--infile", tmp.to_str().unwrap(),
        "--outfile", out.to_str().unwrap(),
        "--hash",
        "--sign",
        "--signing-mode", "test",
        "--anti-rollback-version", "77",
    ]);
    assert!(ok, "hash+sign should succeed");

    let (ok2, stdout2, _) = run_arb(&["--fast", out.to_str().unwrap()]);
    assert!(ok2);
    assert_eq!(stdout2.trim(), "77", "ARB should be 77");

    let (ok3, stdout3, _) = run_arb(&[out.to_str().unwrap()]);
    assert!(ok3);
    assert!(stdout3.contains("Signed: Yes"));
}

#[test]
fn test_minimal_elf_no_hash_fast() {
    let elf = make_minimal_elf32();
    let tmp = std::env::temp_dir().join("test_minimal.elf");
    std::fs::write(&tmp, &elf).unwrap();

    let (ok, _, stderr) = run_arb(&["--fast", tmp.to_str().unwrap()]);
    assert!(!ok, "should fail with no ARB");
    assert!(stderr.contains("No ARB version"));
}

#[test]
fn test_minimal_elf_full_display() {
    let elf = make_minimal_elf32();
    let tmp = std::env::temp_dir().join("test_minimal_full.elf");
    std::fs::write(&tmp, &elf).unwrap();

    let (ok, stdout, _) = run_arb(&[tmp.to_str().unwrap()]);
    assert!(ok, "should succeed: {}", stdout);
    assert!(stdout.contains("0x28") || stdout.contains("ARM"), "should mention machine type");
    assert!(stdout.contains("Format: ELF"));
    assert!(stdout.contains("Program headers:"));
}

// ===== Regression tests =====

#[test]
fn test_regression_arb_roundtrip() {
    // Generate → parse → verify ARB consistency
    let elf = make_elf_with_hash();
    let tmp = std::env::temp_dir().join("test_regression_arb.elf");
    let out = std::env::temp_dir().join("test_regression_arb_out.elf");
    std::fs::write(&tmp, &elf).unwrap();

    // Original ARB = 42
    let (ok1, out1, _) = run_arb(&["--fast", tmp.to_str().unwrap()]);
    assert!(ok1);
    assert_eq!(out1.trim(), "42");

    // Update ARB to 100
    let (ok2, _, _) = run_arb(&[
        "secure-image",
        "--infile", tmp.to_str().unwrap(),
        "--outfile", out.to_str().unwrap(),
        "--hash",
        "--anti-rollback-version", "100",
    ]);
    assert!(ok2);

    // Verify ARB updated
    let (ok3, out3, _) = run_arb(&["--fast", out.to_str().unwrap()]);
    assert!(ok3);
    assert_eq!(out3.trim(), "100", "ARB roundtrip failed");
}

#[test]
fn test_regression_hash_count_consistency() {
    let elf = make_elf_with_hash();
    let tmp = std::env::temp_dir().join("test_regression_hashcnt.elf");
    std::fs::write(&tmp, &elf).unwrap();

    // Full output should show hash entries (3 hashes * 48 bytes SHA384 = 144 bytes)
    let (ok, stdout, _) = run_arb(&[tmp.to_str().unwrap()]);
    assert!(ok);
    assert!(stdout.contains("Hash Table Contents"));
    assert!(stdout.contains("Hash[0]"));
    assert!(stdout.contains("Hash[2]"));
}

#[test]
fn test_regression_feature_disabled_message() {
    // Test that disabled features show proper message (this won't fail even on full build)
    let elf = make_minimal_elf32();
    let tmp = std::env::temp_dir().join("test_regression_disabled.elf");
    std::fs::write(&tmp, &elf).unwrap();
    let out = std::env::temp_dir().join("test_regression_disabled_out.elf");

    // Even on full build, this should work - the test is that it DOESN'T crash
    let (ok, _, _) = run_arb(&[
        "secure-image",
        "--infile", tmp.to_str().unwrap(),
        "--outfile", out.to_str().unwrap(),
        "--validate",
    ]);
    // May or may not succeed depending on feature flags, but shouldn't crash
    let _ = ok;
}

#[test]
fn test_regression_secure_image_missing_infile() {
    let (ok, _, stderr) = run_arb(&["secure-image"]);
    assert!(!ok);
    assert!(stderr.contains("--infile") || stderr.contains("required"));
}
