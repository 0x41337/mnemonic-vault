use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use crate::core::parser::Vault;

pub fn decrypt_file(vault: &Vault, passphrase: &str) -> Result<Vec<u8>> {
    // Decode base64-encoded fields
    let salt = general_purpose::STANDARD
        .decode(&vault.salt)
        .map_err(|_| anyhow::anyhow!("Failed to decode salt: the salt was compromised"))?;

    let nonce_bytes = general_purpose::STANDARD
        .decode(&vault.nonce)
        .map_err(|_| anyhow::anyhow!("Failed to decode nonce: the nonce was compromised"))?;

    let ciphertext = general_purpose::STANDARD
        .decode(&vault.ciphertext)
        .map_err(|_| {
            anyhow::anyhow!("Failed to decode ciphertext: the ciphertext was compromised")
        })?;

    if salt.len() != 16 || nonce_bytes.len() != 12 {
        bail!("Invalid salt or nonce size");
    }

    // Derive key using PBKDF2
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, 100_000, &mut key);

    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Attempt decryption
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Decryption failed: Wrong security phrase."))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::encrypt::encrypt_file;
    use crate::core::parser::Vault;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let plaintext = b"Test secret message";
        let passphrase = "StrongPass123!";

        let vault = encrypt_file(plaintext, passphrase).expect("Encryption failed");

        let decrypted = decrypt_file(&vault, passphrase).expect("Decryption failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_passphrase_fails() {
        let plaintext = b"Sensitive";
        let correct_pass = "CorrectPass";
        let wrong_pass = "WrongPass";

        let vault = encrypt_file(plaintext, correct_pass).unwrap();

        let result = decrypt_file(&vault, wrong_pass);
        assert!(
            result.is_err(),
            "Decryption with wrong passphrase should fail"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Decryption failed"),
            "Expected decryption failure error"
        );
    }

    #[test]
    fn test_decrypt_with_invalid_base64() {
        let vault = Vault {
            salt: "not_base64".into(),
            nonce: "also_invalid".into(),
            ciphertext: "junk".into(),
        };

        let result = decrypt_file(&vault, "pass");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to decode"),
            "Expected base64 decode error"
        );
    }

    #[test]
    fn test_decrypt_with_invalid_nonce_size() {
        use base64::{Engine, engine::general_purpose};

        let vault = Vault {
            salt: general_purpose::STANDARD.encode([0u8; 16]),
            nonce: general_purpose::STANDARD.encode([1u8; 5]), // invalid size
            ciphertext: general_purpose::STANDARD.encode([2u8; 16]),
        };

        let result = decrypt_file(&vault, "pass");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid salt or nonce size"),
            "Expected error due to nonce size"
        );
    }
}
