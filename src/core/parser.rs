use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_vault() {
        let vault = Vault {
            salt: "somesalt".to_string(),
            nonce: "somenonce".to_string(),
            ciphertext: "encrypteddata".to_string(),
        };

        let json = serde_json::to_string(&vault).unwrap();
        assert!(json.contains("somesalt"));
        assert!(json.contains("somenonce"));
        assert!(json.contains("encrypteddata"));
    }

    #[test]
    fn test_deserialize_vault() {
        let json = r#"
        {
            "salt": "somesalt",
            "nonce": "somenonce",
            "ciphertext": "encrypteddata"
        }
        "#;

        let vault: Vault = serde_json::from_str(json).unwrap();
        assert_eq!(vault.salt, "somesalt");
        assert_eq!(vault.nonce, "somenonce");
        assert_eq!(vault.ciphertext, "encrypteddata");
    }

    #[test]
    fn test_round_trip() {
        let original = Vault {
            salt: "abc".to_string(),
            nonce: "def".to_string(),
            ciphertext: "ghi".to_string(),
        };

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Vault = serde_json::from_str(&json).unwrap();

        assert_eq!(original.salt, deserialized.salt);
        assert_eq!(original.nonce, deserialized.nonce);
        assert_eq!(original.ciphertext, deserialized.ciphertext);
    }
}
