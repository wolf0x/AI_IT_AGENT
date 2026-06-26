//! Lightweight encryption utilities for protecting sensitive config values at rest.
//!
//! Uses AES-256-GCM (authenticated encryption) with a key derived from the
//! Windows MachineGuid via SHA-256.  Encrypted values are stored as
//! `ENC:<base64(nonce‖ciphertext‖tag)>` so they can be round-tripped through
//! JSON without any additional metadata fields.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use tracing::warn;

/// Prefix that marks a value as encrypted.
const ENC_PREFIX: &str = "ENC:";

// ── Key derivation ────────────────────────────────────────

/// Derive a 256-bit AES key from the Windows MachineGuid.
///
/// Falls back to a static machine-name-based key when the registry value is
/// unavailable (e.g. non-Windows or permission denied).
fn derive_key() -> [u8; 32] {
    let machine_id = get_machine_guid().unwrap_or_else(|| {
        "rust-agent-fallback-key".to_string()
    });

    let mut hasher = Sha256::new();
    hasher.update(b"rust-agent-mcp-auth-");
    hasher.update(machine_id.as_bytes());
    hasher.finalize().into()
}

/// Read the Windows `MachineGuid` from the registry.
#[cfg(target_os = "windows")]
fn get_machine_guid() -> Option<String> {
    use std::process::Command;
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "MachineGuid" {
            return Some(parts.last()?.to_string());
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn get_machine_guid() -> Option<String> {
    std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|s| s.trim().to_string())
}

// ── Public API ────────────────────────────────────────────

/// Encrypt a plaintext string.  Returns `ENC:<base64>` or empty string.
pub fn encrypt(plaintext: &str) -> String {
    if plaintext.is_empty() {
        return String::new();
    }
    let key = derive_key();
    let cipher = Aes256Gcm::new_from_slice(&key).expect("valid key size");

    // Random 96-bit nonce
    let nonce_bytes = generate_random_bytes(12);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("encryption should not fail");

    // Encode: nonce (12 bytes) ‖ ciphertext+tag
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    format!("{}{}", ENC_PREFIX, base64_encode(&combined))
}

/// Decrypt a value that was encrypted with [`encrypt`].  If the value does not
/// start with `ENC:` it is returned as-is (assumed to be plaintext).
pub fn decrypt(maybe_encrypted: &str) -> String {
    if !maybe_encrypted.starts_with(ENC_PREFIX) {
        return maybe_encrypted.to_string();
    }
    let encoded = &maybe_encrypted[ENC_PREFIX.len()..];
    let combined = match base64_decode(encoded) {
        Some(v) => v,
        None => {
            warn!("Failed to base64-decode encrypted value, returning as-is");
            return maybe_encrypted.to_string();
        }
    };

    if combined.len() < 12 {
        warn!("Encrypted value too short, returning as-is");
        return maybe_encrypted.to_string();
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let key = derive_key();
    let cipher = Aes256Gcm::new_from_slice(&key).expect("valid key size");
    let nonce = Nonce::from_slice(nonce_bytes);

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext_bytes) => {
            String::from_utf8(plaintext_bytes).unwrap_or_else(|_| {
                warn!("Decrypted value is not valid UTF-8");
                maybe_encrypted.to_string()
            })
        }
        Err(_) => {
            warn!("Decryption failed (key may have changed), returning raw value");
            maybe_encrypted.to_string()
        }
    }
}

/// Returns `true` if the value looks like it was encrypted by us.
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENC_PREFIX)
}

// ── Helpers ───────────────────────────────────────────────

fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("failed to get random bytes");
    buf
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in input.as_bytes() {
        let val = match byte {
            b'A'..=b'Z' => (byte - b'A') as u32,
            b'a'..=b'z' => (byte - b'a' + 26) as u32,
            b'0'..=b'9' => (byte - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let plaintext = "sk-my-secret-token-12345";
        let encrypted = encrypt(plaintext);
        assert!(encrypted.starts_with(ENC_PREFIX));
        assert_ne!(encrypted, plaintext);
        let decrypted = decrypt(&encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn plaintext_passthrough() {
        let plain = "not-encrypted";
        assert_eq!(decrypt(plain), plain);
    }

    #[test]
    fn empty_string() {
        assert_eq!(encrypt(""), "");
        assert_eq!(decrypt(""), "");
    }
}
