#[cfg(feature = "hash-gen")]
pub mod recompute;

#[cfg(feature = "hash-gen")]
pub fn build_hash_segment(
    elf_data: &[u8],
    program_headers: &[crate::elf::program_header::ProgramHeader],
    elf_header: &crate::elf::header::ElfHeader,
    hash_version: u32,
    hash_algo: crate::config::profile::HashAlgorithm,
    oem_metadata: Option<&crate::hash_segment::metadata::MetadataV20>,
    _device_restrictions: Option<&crate::config::device_restrictions::DeviceRestrictions>,
    _encryption_params: Option<&crate::hash_segment::encryption::EncryptionParams>,
) -> crate::error::Result<Vec<u8>> {
    use crate::data::*;
    use crate::elf::defines::{p_flags_os_segment_type, P_FLAGS_OS_SEGMENT_HASH};
    use crate::hash_segment::defines;
    use crate::hash_segment::header::HashTableSegmentHeaderV7;
    use crate::hash_segment::metadata::CommonMetadataV00;

    let hash_entry_size = hash_algo.digest_size();
    let num_segments = program_headers
        .iter()
        .filter(|ph| p_flags_os_segment_type(ph.p_flags) != P_FLAGS_OS_SEGMENT_HASH)
        .count();
    let hash_table_size = (hash_entry_size * num_segments) as u32;

    let (header_bytes, hdr_size) = match hash_version {
        7 => {
            let hdr = HashTableSegmentHeaderV7 {
                reserved: 0,
                version: 7,
                common_metadata_size: CommonMetadataV00::SIZE as u32,
                qti_metadata_size: 0,
                oem_metadata_size: crate::hash_segment::metadata::MetadataV20::SIZE as u32,
                hash_table_size,
                qti_signature_size: 0,
                qti_certificate_chain_size: 0,
                oem_signature_size: 0,
                oem_certificate_chain_size: 0,
            };
            let mut buf = vec![0u8; defines::HASH_TABLE_HEADER_SIZE_V7];
            buf[0..4].copy_from_slice(&hdr.reserved.to_le_bytes());
            buf[4..8].copy_from_slice(&hdr.version.to_le_bytes());
            buf[8..12].copy_from_slice(&hdr.common_metadata_size.to_le_bytes());
            buf[12..16].copy_from_slice(&hdr.qti_metadata_size.to_le_bytes());
            buf[16..20].copy_from_slice(&hdr.oem_metadata_size.to_le_bytes());
            buf[20..24].copy_from_slice(&hdr.hash_table_size.to_le_bytes());
            buf[24..28].copy_from_slice(&hdr.qti_signature_size.to_le_bytes());
            buf[28..32].copy_from_slice(&hdr.qti_certificate_chain_size.to_le_bytes());
            buf[32..36].copy_from_slice(&hdr.oem_signature_size.to_le_bytes());
            buf[36..40].copy_from_slice(&hdr.oem_certificate_chain_size.to_le_bytes());
            (buf, defines::HASH_TABLE_HEADER_SIZE_V7)
        }
        _ => {
            return Err(crate::error::Error::UnsupportedHashSegmentVersion(hash_version));
        }
    };

    let mut segment = Vec::new();
    segment.extend_from_slice(&header_bytes);

    // Common metadata (24 bytes)
    let cm = CommonMetadataV00 {
        major_version: 0,
        minor_version: 0,
        software_id: 0,
        secondary_software_id: 0,
        hash_table_algorithm: match hash_algo {
            crate::config::profile::HashAlgorithm::Sha256 => 2,
            crate::config::profile::HashAlgorithm::Sha384 => 3,
            crate::config::profile::HashAlgorithm::Sha512 => 5,
        },
        measurement_register_target: 0,
    };
    let mut cm_buf = vec![0u8; CommonMetadataV00::SIZE];
    cm_buf[0..4].copy_from_slice(&cm.major_version.to_le_bytes());
    cm_buf[4..8].copy_from_slice(&cm.minor_version.to_le_bytes());
    cm_buf[8..12].copy_from_slice(&cm.software_id.to_le_bytes());
    cm_buf[12..16].copy_from_slice(&cm.secondary_software_id.to_le_bytes());
    cm_buf[16..20].copy_from_slice(&cm.hash_table_algorithm.to_le_bytes());
    cm_buf[20..24].copy_from_slice(&cm.measurement_register_target.to_le_bytes());
    segment.extend_from_slice(&cm_buf);

    if let Some(om) = oem_metadata {
        let meta_bytes = serialize_metadata_v20(om);
        segment.extend_from_slice(&meta_bytes);
    }

    let hashes = recompute::compute_segment_hashes(elf_data, program_headers, elf_header, hash_algo)?;
    for hash in &hashes {
        segment.extend_from_slice(hash);
    }

    if let Some(enc) = _encryption_params {
        let enc_bytes = crate::encrypt::serialize(enc);
        segment.extend_from_slice(&enc_bytes);
    }

    Ok(segment)
}

fn serialize_metadata_v20(m: &crate::hash_segment::metadata::MetadataV20) -> Vec<u8> {
    let mut buf = vec![0u8; crate::hash_segment::metadata::MetadataV20::SIZE];
    let arr = &mut buf;
    // V2.0 224B layout
    arr[0..4].copy_from_slice(&m.major_version.to_le_bytes());
    arr[4..8].copy_from_slice(&m.minor_version.to_le_bytes());
    arr[8..12].copy_from_slice(&m.anti_rollback_version.to_le_bytes());
    arr[12..16].copy_from_slice(&m.mrc_index.to_le_bytes());
    for i in 0..12.min(m.soc_hw_vers.len()) {
        let off = 16 + i * 4;
        arr[off..off + 4].copy_from_slice(&m.soc_hw_vers[i].to_le_bytes());
    }
    arr[64..68].copy_from_slice(&m.soc_feature_id.to_le_bytes());
    arr[68..72].copy_from_slice(&m.jtag_id.to_le_bytes());
    for i in 0..8.min(m.serial_numbers.len()) {
        let off = 72 + i * 8;
        arr[off..off + 8].copy_from_slice(&m.serial_numbers[i].to_le_bytes());
    }
    arr[136..140].copy_from_slice(&m.oem_id.to_le_bytes());
    arr[140..144].copy_from_slice(&m.oem_product_id.to_le_bytes());
    arr[144..148].copy_from_slice(&m.soc_lifecycle_state.to_le_bytes());
    arr[148..152].copy_from_slice(&m.oem_lifecycle_state.to_le_bytes());
    arr[152..156].copy_from_slice(&m.oem_root_certificate_hash_algorithm.to_le_bytes());
    arr[156..220].copy_from_slice(&m.oem_root_certificate_hash);
    arr[220..224].copy_from_slice(&m.flags.to_le_bytes());
    buf
}

#[cfg(not(feature = "hash-gen"))]
pub fn build_hash_segment(
    _elf_data: &[u8],
    _program_headers: &[crate::elf::program_header::ProgramHeader],
    _elf_header: &crate::elf::header::ElfHeader,
    _hash_version: u32,
    _hash_algo: crate::config::profile::HashAlgorithm,
    _oem_metadata: Option<&crate::hash_segment::metadata::MetadataV20>,
    _device_restrictions: Option<&crate::config::device_restrictions::DeviceRestrictions>,
    _encryption_params: Option<&crate::hash_segment::encryption::EncryptionParams>,
) -> crate::error::Result<Vec<u8>> {
    Err(crate::error::Error::Custom(
        "Hash segment generation not supported in this build".into(),
    ))
}
