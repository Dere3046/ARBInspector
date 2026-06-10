use crate::config::device_restrictions::DeviceRestrictions;
use crate::config::profile::{SecurityProfile, SigningMode};
use crate::core::encryption_order::{self, Operation};
use crate::data::read_le_u32;
use crate::elf::defines::p_flags_os_segment_type;
use crate::elf::header::ElfHeader;
use crate::elf::parser::ElfParser;
use crate::elf::program_header::ProgramHeader;
use crate::error::{Error, Result};

#[cfg(feature = "sign")]
use crate::sign::{local::LocalSigner, test::TestSigner, Signer};
#[cfg(feature = "hash-gen")]
use crate::hash_segment::metadata::MetadataV20;

pub struct Pipeline<'a> {
    pub profile: &'a SecurityProfile,
    pub data: Vec<u8>,
    pub operations: Vec<Operation>,
    pub device_restrictions: Option<&'a DeviceRestrictions>,
}

impl<'a> Pipeline<'a> {
    pub fn new(
        profile: &'a SecurityProfile,
        data: &[u8],
        device_restrictions: Option<&'a DeviceRestrictions>,
    ) -> Self {
        Pipeline {
            profile,
            data: data.to_vec(),
            operations: Vec::new(),
            device_restrictions,
        }
    }

    pub fn set_operations(&mut self, ops: &[Operation]) {
        let ordered = encryption_order::order_of_operations(
            self.profile.encrypt.as_ref().map(|e| e.etype),
            self.profile.encrypt.as_ref().map(|e| e.order),
            ops,
        );
        self.operations = ordered;
    }

    pub fn run(&mut self) -> Result<&[u8]> {
        let ops = self.operations.clone();
        for op in &ops {
            match op {
                Operation::Hash => self.do_hash()?,
                Operation::Sign => self.do_sign()?,
                Operation::Encrypt => self.do_encrypt()?,
            }
        }
        Ok(&self.data)
    }

    fn parse_phdrs(data: &[u8]) -> Result<Vec<ProgramHeader>> {
        ElfParser::from_bytes(data)
            .map(|p| p.program_headers.clone())
            .map_err(|e| Error::ElfParse(e.to_string()))
    }

    fn find_hash_phdr(phdrs: &[ProgramHeader]) -> Option<&ProgramHeader> {
        phdrs.iter().find(|ph| p_flags_os_segment_type(ph.p_flags) == 2)
    }

    fn inject_data(&mut self, offset: usize, new_data: &[u8]) {
        let max_size = (self.data.len() - offset).min(0x10000);
        let copy_len = new_data.len().min(max_size);
        if offset + copy_len <= self.data.len() {
            self.data[offset..offset + copy_len].copy_from_slice(&new_data[..copy_len]);
        }
    }

    fn do_hash(&mut self) -> Result<()> {
        #[cfg(not(feature = "hash-gen"))]
        return Err(Error::Custom("Hash generation not supported in this build".into()));

        #[cfg(feature = "hash-gen")]
        {
            let phdrs = Self::parse_phdrs(&self.data)?;
            let phdr = Self::find_hash_phdr(&phdrs)
                .ok_or_else(|| Error::Custom("No HASH segment PHDR found".into()))?;
            let elf_header = ElfHeader::from_bytes(&self.data)
                .map_err(|e| Error::ElfParse(e.to_string()))?;

            let oem_meta = MetadataV20 {
                major_version: 3, minor_version: 0,
                anti_rollback_version: self.device_restrictions.and_then(|r| r.anti_rollback_version).unwrap_or(0),
                mrc_index: 0, soc_hw_vers: Vec::new(),
                soc_feature_id: self.device_restrictions.and_then(|r| r.soc_feature_id).unwrap_or(0),
                jtag_id: self.device_restrictions.and_then(|r| r.jtag_id).unwrap_or(0),
                serial_numbers: Vec::new(),
                oem_id: self.device_restrictions.and_then(|r| r.oem_id).unwrap_or(0),
                oem_product_id: self.device_restrictions.and_then(|r| r.oem_product_id).unwrap_or(0),
                soc_lifecycle_state: self.device_restrictions.and_then(|r| r.soc_lifecycle_state).unwrap_or(0),
                oem_lifecycle_state: self.device_restrictions.and_then(|r| r.oem_lifecycle_state).unwrap_or(0),
                oem_root_certificate_hash_algorithm: 0,
                oem_root_certificate_hash: [0; 64],
                flags: self.device_restrictions.and_then(|r| r.flags).unwrap_or(0),
            };

            let seg_data = crate::hash_segment::writer::build_hash_segment(
                &self.data, &phdrs, &elf_header,
                7, self.profile.hash_algorithm,
                Some(&oem_meta), self.device_restrictions, None,
            )?;
            self.inject_data(phdr.p_offset as usize, &seg_data);
            Ok(())
        }
    }

    fn do_sign(&mut self) -> Result<()> {
        #[cfg(not(feature = "sign"))]
        return Err(Error::Custom("Signing not supported in this build".into()));

        #[cfg(feature = "sign")]
        {
            let phdrs = Self::parse_phdrs(&self.data)?;
            let phdr = Self::find_hash_phdr(&phdrs)
                .ok_or_else(|| Error::Custom("No HASH segment PHDR found".into()))?;
            let hash_off = phdr.p_offset as usize;
            let hash_end = (hash_off + phdr.p_filesz as usize).min(self.data.len());
            let hash_seg = &self.data[hash_off..hash_end];

            // Parse header
            let hdr = &hash_seg[..40];
            let cm_size = read_le_u32(hdr, 8) as usize;
            let qti_meta_size = read_le_u32(hdr, 12) as usize;
            let oem_meta_size = read_le_u32(hdr, 16) as usize;
            let hash_table_size = read_le_u32(hdr, 20) as usize;

            // data_to_sign = header + common_metadata + qti_metadata + oem_metadata + hash_table
            let meta_end = 40 + cm_size + qti_meta_size + oem_meta_size;
            let data_end = meta_end + hash_table_size;
            if data_end > hash_seg.len() {
                return Err(Error::Custom("Hash segment too short for metadata + hash table".into()));
            }
            let data_to_sign = &hash_seg[..data_end];

            let signer: Box<dyn Signer> = match &self.profile.sign {
                Some(cfg) => match cfg.mode {
                    SigningMode::Test => Box::new(TestSigner::new(
                        "ecdsa", "sha384", None, None, Some("secp384r1"), None, 0,
                        cfg.cert_chain_depth,
                    )?),
                    SigningMode::Local => Box::new(LocalSigner::new_ecdsa(
                        Vec::new(), Vec::new(), Vec::new(), Vec::new(), "secp384r1",
                    )?),
                    SigningMode::Plugin => {
                        return Err(Error::Custom("plugin signer not yet wired in pipeline".into()))
                    }
                },
                None => return Err(Error::Custom("no sign config in profile".into())),
            };

            let (signature, cert_chain) = signer.sign(data_to_sign)?;

            // Calculate sizes for total sig+cert chain blob
            let qti_sig_size = signature.len();
            let qti_cert_size: usize = cert_chain.iter().map(|c| c.len()).sum();

            // Build injection buffer: [signature][cert_chain_concatenated]
            let mut sig_block = Vec::new();
            sig_block.extend_from_slice(&signature);
            for cert in &cert_chain {
                sig_block.extend_from_slice(cert);
            }

            // Check: sig_block must fit after hash table
            let sig_off = hash_off + data_end;
            let sig_end = sig_off + sig_block.len();
            if sig_end > self.data.len() {
                // Try to extend data
                self.data.resize(sig_end, 0xFF);
            }
            if sig_off + sig_block.len() <= self.data.len() {
                self.data[sig_off..sig_off + sig_block.len()].copy_from_slice(&sig_block);
            }

            // Update header fields in-place
            let hdr_sig_size_off = hash_off + 24; // qti_signature_size at offset 24
            let hdr_cert_size_off = hash_off + 28; // qti_certificate_chain_size at offset 28
            let sig_size_bytes = (qti_sig_size as u32).to_le_bytes();
            let cert_size_bytes = (qti_cert_size as u32).to_le_bytes();
            if hash_off + 32 <= self.data.len() {
                self.data[hdr_sig_size_off..hdr_sig_size_off + 4].copy_from_slice(&sig_size_bytes);
                self.data[hdr_cert_size_off..hdr_cert_size_off + 4].copy_from_slice(&cert_size_bytes);
            }

            Ok(())
        }
    }

    fn do_encrypt(&mut self) -> Result<()> {
        #[cfg(not(feature = "encrypt"))]
        return Err(Error::Custom("Encryption not supported in this build".into()));

        #[cfg(feature = "encrypt")]
        {
            Ok(())
        }
    }
}
