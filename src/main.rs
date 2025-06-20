mod core;

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use clap::{Parser, Subcommand};

use zeroize::Zeroize;

use cliclack::{intro, outro, password, spinner};

/// mnemonic-vault: A cryptographic vault for your files that can only be accessed with your passphrase.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a text file with a mnemonic seed
    Lock {
        /// Path of the raw file you want to encrypt
        #[arg(short, long)]
        target: String,

        /// Encrypted Buffer Output Path
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Decrypt an encrypted file and reveal its contents
    Unlock {
        /// Path of the encrypted file you want to reveal
        #[arg(short, long)]
        target: String,

        /// Revealed Content Output Path
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn lock_file(target: &str, output: &Option<String>) -> Result<()> {
    intro(format!("Locking file: {}", target))?;

    // Check if file exists
    let path = Path::new(target);
    if !path.exists() || !path.is_file() {
        anyhow::bail!("File not found: {}", target);
    }

    // Request authentication phrase and validate password strength
    let mut pass = password("Provide a strength phrase")
        .validate_on_enter(core::validation::validate_passphrase)
        .interact()?;

    // Reads file contents
    let plaintext = fs::read(path).with_context(|| format!("Error reading file: {}", target))?;

    // Encrypts
    let sp = spinner();
    sp.start("Encrypting...");

    let vault = core::encrypt::encrypt_file(&plaintext, &pass)?;

    sp.stop("File encrypted successfully!");

    // Define output path
    let output_path = output.clone().unwrap_or_else(|| {
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let filename = path.file_name().unwrap_or_default().to_string_lossy();
        parent
            .join(format!("{}.lock", filename))
            .to_string_lossy()
            .to_string()
    });

    // Serialize JSON and save
    let json = serde_json::to_string_pretty(&vault)?;

    fs::write(&output_path, json)
        .with_context(|| format!("Error saving encrypted file: {}", output_path))?;

    outro(format!("File saved as: {}", output_path))?;

    // Clear sensitive data from the memory
    pass.zeroize();

    Ok(())
}

fn unlock_file(target: &str, output: &Option<String>) -> Result<()> {
    intro(format!("Unlocking file: {}", target))?;

    // Check if file exists
    let path = Path::new(target);
    if !path.exists() || !path.is_file() {
        anyhow::bail!("File not found: {}", target);
    }

    // Read the encrypted file contents (JSON)
    let json =
        fs::read_to_string(path).with_context(|| format!("Error reading file: {}", target))?;

    // Deserialize Vault
    let vault: core::parser::Vault =
        serde_json::from_str(&json).with_context(|| format!("Failed to parse encrypted file"))?;

    // Ask password (hidden input)
    let mut pass = password("Provide your passphrase").interact()?;

    // Decrypt content
    let sp = spinner();
    sp.start("Decrypting...");

    let plaintext = core::decrypt::decrypt_file(&vault, &pass)?;

    sp.stop("File decrypted successfully!");

    // Define output path (default: original filename without `.lock`)
    let output_path = output.clone().unwrap_or_else(|| {
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let filename = path.file_stem().unwrap_or_default().to_string_lossy();
        parent
            .join(filename.to_string())
            .to_string_lossy()
            .to_string()
    });

    // Write decrypted plaintext to output file
    fs::write(&output_path, plaintext)
        .with_context(|| format!("Error saving decrypted file: {}", output_path))?;

    outro(format!("File decrypted and saved as: {}", output_path))?;

    // Clear sensitive data from the memory
    pass.zeroize();

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Lock { target, output } => {
            lock_file(&target, output)?;
        }

        Commands::Unlock { target, output } => {
            unlock_file(&target, output)?;
        }
    }

    Ok(())
}
