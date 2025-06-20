use crate::core::parser::Vault;

use rand::prelude::*;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use pbkdf2::pbkdf2_hmac;

use sha2::Sha256;

pub fn encrypt_file(plaintext: &[u8], passphrase: &str) -> Result<Vault> {
    // Generate salt
    let mut rng = rand::rng();
    let mut salt = [0u8; 16];

    rng.fill_bytes(&mut salt);

    // Derive key using PBKDF2
    let mut key = [0u8; 32]; // 256 bits
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, 100_000, &mut key);

    // Create AES-GCM cipher
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    // Generate nonce (12 bytes)
    let mut nonce_bytes = [0u8; 12];

    rng.fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

    // Build Vault object
    Ok(Vault {
        salt: general_purpose::STANDARD.encode(salt),
        nonce: general_purpose::STANDARD.encode(nonce_bytes),
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;

    #[test]
    fn test_encrypt_file_creates_vault() {
        let plaintext = b"Secret data!";
        let passphrase = "StrongPassphrase!";

        let result = encrypt_file(plaintext, passphrase).expect("Encryption should succeed");

        // Validate structure
        assert!(!result.salt.is_empty(), "Salt should not be empty");
        assert!(!result.nonce.is_empty(), "Nonce should not be empty");
        assert!(
            !result.ciphertext.is_empty(),
            "Ciphertext should not be empty"
        );

        // Validate base64 decoding
        let salt_bytes = general_purpose::STANDARD
            .decode(&result.salt)
            .expect("Salt should be valid base64");
        let nonce_bytes = general_purpose::STANDARD
            .decode(&result.nonce)
            .expect("Nonce should be valid base64");
        let ciphertext_bytes = general_purpose::STANDARD
            .decode(&result.ciphertext)
            .expect("Ciphertext should be valid base64");

        assert_eq!(salt_bytes.len(), 16, "Salt must be 16 bytes");
        assert_eq!(nonce_bytes.len(), 12, "Nonce must be 12 bytes");
        assert!(
            ciphertext_bytes.len() > 0,
            "Ciphertext must have non-zero length"
        );
    }

    #[test]
    fn test_encrypt_file_different_salt_and_nonce_each_time() {
        let plaintext = b"Same plaintext";
        let passphrase = "SamePassphrase";

        let vault1 = encrypt_file(plaintext, passphrase).unwrap();
        let vault2 = encrypt_file(plaintext, passphrase).unwrap();

        // With different random salt/nonce, the ciphertext should differ
        assert_ne!(vault1.salt, vault2.salt, "Salt should be random");
        assert_ne!(vault1.nonce, vault2.nonce, "Nonce should be random");
        assert_ne!(
            vault1.ciphertext, vault2.ciphertext,
            "Ciphertext should differ with different salt/nonce"
        );
    }

    #[test]
    fn test_encrypt_file_empty_plaintext() {
        let plaintext = b"";
        let passphrase = "Passphrase";

        let result = encrypt_file(plaintext, passphrase)
            .expect("Encryption of empty plaintext should succeed");

        // Base64 ciphertext of empty input may still produce bytes (AES-GCM adds tag)
        assert!(
            !result.ciphertext.is_empty(),
            "Ciphertext should still be present"
        );
    }
}
