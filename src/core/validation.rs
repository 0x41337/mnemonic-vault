use anyhow::{Result, bail};

pub fn validate_passphrase(phrase: &String) -> Result<()> {
    if phrase.len() < 10 {
        bail!("Passphrase must be at least 10 characters.");
    }

    if !phrase.chars().any(|c| c.is_uppercase()) {
        bail!("Passphrase must contain at least one uppercase letter.");
    }

    if !phrase.chars().any(|c| !c.is_alphanumeric()) {
        bail!("Passphrase must contain at least one special character.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_passphrase() {
        let result = validate_passphrase(&String::from("Valid$Pass1"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_short_passphrase() {
        let result = validate_passphrase(&String::from("Short$1"));
        assert_eq!(
            result.unwrap_err().to_string(),
            "Passphrase must be at least 10 characters."
        );
    }

    #[test]
    fn test_missing_uppercase() {
        let result = validate_passphrase(&String::from("valid$pass1"));
        assert_eq!(
            result.unwrap_err().to_string(),
            "Passphrase must contain at least one uppercase letter."
        );
    }

    #[test]
    fn test_missing_special_character() {
        let result = validate_passphrase(&String::from("ValidPass1"));
        assert_eq!(
            result.unwrap_err().to_string(),
            "Passphrase must contain at least one special character."
        );
    }

    #[test]
    fn test_all_conditions_fail() {
        let result = validate_passphrase(&String::from("short"));
        assert_eq!(
            result.unwrap_err().to_string(),
            "Passphrase must be at least 10 characters."
        );
    }
}
