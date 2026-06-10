use std::path::Path;
use std::process::{Command, Stdio};
use std::io::{Read, Write};

use crate::error::{Error, Result};
use crate::sign::base_signer::Signer;

pub struct PluginSigner {
    plugin_path: String,
    plugin_args: Vec<String>,
}

impl PluginSigner {
    pub fn new(plugin_path: String, plugin_args: Vec<String>) -> Result<Self> {
        let path = Path::new(&plugin_path);
        if !path.exists() {
            return Err(Error::Custom(format!(
                "Plugin path does not exist: {}",
                plugin_path
            )));
        }
        if !path.is_file() {
            return Err(Error::Custom(format!(
                "Plugin path is not a file: {}",
                plugin_path
            )));
        }
        Ok(PluginSigner {
            plugin_path,
            plugin_args,
        })
    }
}

impl Signer for PluginSigner {
    fn name(&self) -> &str {
        "plugin"
    }

    fn sign(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
        let mut child = Command::new(&self.plugin_path)
            .args(&self.plugin_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                Error::Custom(format!("Failed to spawn plugin '{}': {}", self.plugin_path, e))
            })?;

        if let Some(ref mut stdin) = child.stdin {
            stdin.write_all(data).map_err(|e| {
                Error::Custom(format!("Failed to write data to plugin stdin: {}", e))
            })?;
        }

        let mut stdout = Vec::new();
        if let Some(ref mut out) = child.stdout {
            out.read_to_end(&mut stdout).map_err(|e| {
                Error::Custom(format!("Failed to read plugin stdout: {}", e))
            })?;
        }

        let status = child.wait().map_err(|e| {
            Error::Custom(format!("Failed to wait for plugin: {}", e))
        })?;

        if !status.success() {
            let mut stderr = Vec::new();
            if let Some(ref mut err) = child.stderr {
                err.read_to_end(&mut stderr).ok();
            }
            let msg = String::from_utf8_lossy(&stderr);
            return Err(Error::Custom(format!(
                "Plugin exited with status {}: {}",
                status,
                msg.trim()
            )));
        }

        if stdout.len() < 4 {
            return Err(Error::Custom(format!(
                "Plugin output too short: {} bytes, need at least 4 for signature length header",
                stdout.len()
            )));
        }

        let sig_len = u32::from_le_bytes(stdout[..4].try_into().unwrap()) as usize;
        let payload_offset = 4 + sig_len;

        if payload_offset > stdout.len() {
            return Err(Error::Custom(format!(
                "Plugin output truncated: signature length {} but only {} bytes remain after header",
                sig_len,
                stdout.len() - 4
            )));
        }

        let signature = stdout[4..payload_offset].to_vec();
        let cert_chain_der = &stdout[payload_offset..];

        let mut certs = Vec::new();
        let mut offset = 0;
        while offset < cert_chain_der.len() {
            let remaining = &cert_chain_der[offset..];
            if remaining[0] != 0x30 {
                certs.push(remaining.to_vec());
                break;
            }
            let len = match der_length(remaining) {
                Some(l) => l,
                None => {
                    certs.push(remaining.to_vec());
                    break;
                }
            };
            let end = (offset + len).min(cert_chain_der.len());
            certs.push(cert_chain_der[offset..end].to_vec());
            offset = end;
        }

        Ok((signature, certs))
    }
}

fn der_length(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    if data[1] & 0x80 == 0 {
        Some(data[1] as usize + 2)
    } else {
        let num_bytes = (data[1] & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || 2 + num_bytes > data.len() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[2 + i] as usize;
        }
        Some(len + 2 + num_bytes)
    }
}
