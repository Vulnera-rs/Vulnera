//! Credential Manager - Secure storage for API keys and tokens
//!
//! This module provides encrypted credential storage using:
//! 1. OS keyring (preferred) - macOS Keychain, Windows Credential Manager, Linux Secret Service
//! 2. AES-256-GCM encrypted file (fallback) - for headless systems without keyring support

use std::fs;
use std::path::PathBuf;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

const SERVICE_NAME: &str = "vulnera-cli";
const KEYRING_USER: &str = "api_key";
const ENCRYPTED_FILE_NAME: &str = "credentials.enc";
const ENCRYPTION_KEY_FILE: &str = "key.bin";

/// Manages secure storage and retrieval of credentials
pub struct CredentialManager {
    /// Data directory for encrypted file fallback
    data_dir: PathBuf,

    /// Whether OS keyring is available
    keyring_available: bool,
}

/// Encrypted credential file format
#[derive(Serialize, Deserialize)]
struct EncryptedCredentials {
    /// Nonce used for encryption (12 bytes, base64 encoded)
    nonce: String,
    /// Encrypted data (base64 encoded)
    data: String,
}

/// Plaintext credentials (before encryption)
#[derive(Serialize, Deserialize, Default)]
struct Credentials {
    api_key: Option<String>,
    server_url: Option<String>,
}

impl CredentialManager {
    /// Create a new credential manager
    pub fn new() -> Result<Self> {
        let data_dir = Self::get_data_dir()?;

        // Ensure data directory exists
        fs::create_dir_all(&data_dir)
            .with_context(|| format!("Failed to create data directory: {:?}", data_dir))?;

        // Check if keyring is available
        let keyring_available = Self::check_keyring_available();

        Ok(Self {
            data_dir,
            keyring_available,
        })
    }

    /// Get the data directory for credential storage
    fn get_data_dir() -> Result<PathBuf> {
        ProjectDirs::from("dev", "vulnera", "vulnera-cli")
            .map(|dirs| dirs.data_dir().to_path_buf())
            .context("Failed to determine data directory")
    }

    /// Check if OS keyring is available
    fn check_keyring_available() -> bool {
        let entry = keyring::Entry::new(SERVICE_NAME, "test");
        match entry {
            Ok(e) => {
                // Try to access (will fail gracefully if no keyring)
                match e.get_password() {
                    Ok(_) | Err(keyring::Error::NoEntry) => true,
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }

    /// Store API key securely
    pub fn store_api_key(&self, api_key: &str) -> Result<()> {
        if self.keyring_available {
            self.store_in_keyring(api_key)
        } else {
            self.store_in_file(api_key)
        }
    }

    /// Retrieve stored API key
    pub fn get_api_key(&self) -> Result<Option<String>> {
        if self.keyring_available {
            self.get_from_keyring()
        } else {
            self.get_from_file()
        }
    }

    /// Delete stored API key
    pub fn delete_api_key(&self) -> Result<()> {
        if self.keyring_available {
            self.delete_from_keyring()
        } else {
            self.delete_from_file()
        }
    }

    /// Check if credentials are stored
    pub fn has_credentials(&self) -> bool {
        self.get_api_key().ok().flatten().is_some()
    }

    /// Get the storage method being used
    pub fn storage_method(&self) -> &'static str {
        if self.keyring_available {
            "OS Keyring"
        } else {
            "Encrypted File"
        }
    }

    // ========================
    // Keyring implementation
    // ========================

    fn store_in_keyring(&self, api_key: &str) -> Result<()> {
        let entry = keyring::Entry::new(SERVICE_NAME, KEYRING_USER)
            .context("Failed to create keyring entry")?;

        entry
            .set_password(api_key)
            .context("Failed to store API key in keyring")?;

        Ok(())
    }

    fn get_from_keyring(&self) -> Result<Option<String>> {
        let entry = keyring::Entry::new(SERVICE_NAME, KEYRING_USER)
            .context("Failed to create keyring entry")?;

        match entry.get_password() {
            Ok(password) => Ok(Some(password)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Failed to retrieve API key: {}", e)),
        }
    }

    fn delete_from_keyring(&self) -> Result<()> {
        let entry = keyring::Entry::new(SERVICE_NAME, KEYRING_USER)
            .context("Failed to create keyring entry")?;

        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // Already deleted
            Err(e) => Err(anyhow::anyhow!("Failed to delete API key: {}", e)),
        }
    }

    // ========================
    // Encrypted file implementation
    // ========================

    fn get_encryption_key(&self) -> Result<[u8; 32]> {
        let key_path = self.data_dir.join(ENCRYPTION_KEY_FILE);

        if key_path.exists() {
            // Load existing key
            let key_bytes = fs::read(&key_path)
                .with_context(|| format!("Failed to read encryption key from {:?}", key_path))?;

            if key_bytes.len() != 32 {
                // Key file corrupted, regenerate
                tracing::warn!("Encryption key corrupted, regenerating...");
                return self.generate_encryption_key();
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            Ok(key)
        } else {
            self.generate_encryption_key()
        }
    }

    fn generate_encryption_key(&self) -> Result<[u8; 32]> {
        use aes_gcm::aead::rand_core::RngCore;

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let key_path = self.data_dir.join(ENCRYPTION_KEY_FILE);

        // Set restrictive permissions before writing (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_path)
                .with_context(|| format!("Failed to create key file: {:?}", key_path))?;

            use std::io::Write;
            file.write_all(&key)?;
        }

        #[cfg(not(unix))]
        fs::write(&key_path, &key)
            .with_context(|| format!("Failed to write encryption key to {:?}", key_path))?;

        Ok(key)
    }

    fn store_in_file(&self, api_key: &str) -> Result<()> {
        let key = self.get_encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key).context("Failed to create cipher")?;

        // Generate random nonce
        use aes_gcm::aead::rand_core::RngCore;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create credentials struct
        let credentials = Credentials {
            api_key: Some(api_key.to_string()),
            server_url: None,
        };

        let plaintext =
            serde_json::to_vec(&credentials).context("Failed to serialize credentials")?;

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Save encrypted credentials
        let encrypted = EncryptedCredentials {
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes),
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ciphertext),
        };

        let file_path = self.data_dir.join(ENCRYPTED_FILE_NAME);
        let json = serde_json::to_string_pretty(&encrypted)
            .context("Failed to serialize encrypted credentials")?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&file_path)
                .with_context(|| format!("Failed to create credentials file: {:?}", file_path))?;

            use std::io::Write;
            file.write_all(json.as_bytes())?;
        }

        #[cfg(not(unix))]
        fs::write(&file_path, &json)
            .with_context(|| format!("Failed to write credentials to {:?}", file_path))?;

        Ok(())
    }

    fn get_from_file(&self) -> Result<Option<String>> {
        let file_path = self.data_dir.join(ENCRYPTED_FILE_NAME);

        if !file_path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read credentials from {:?}", file_path))?;

        let encrypted: EncryptedCredentials = match serde_json::from_str(&json) {
            Ok(e) => e,
            Err(_) => {
                tracing::warn!("Credentials file corrupted, resetting...");
                self.delete_from_file()?;
                return Ok(None);
            }
        };

        let key = self.get_encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key).context("Failed to create cipher")?;

        // Decode nonce and ciphertext
        let nonce_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encrypted.nonce)
                .context("Failed to decode nonce")?;

        let ciphertext =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encrypted.data)
                .context("Failed to decode ciphertext")?;

        if nonce_bytes.len() != 12 {
            tracing::warn!("Invalid nonce length, resetting credentials...");
            self.delete_from_file()?;
            return Ok(None);
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
            tracing::warn!("Failed to decrypt credentials, resetting...");
            anyhow::anyhow!("Decryption failed")
        })?;

        let credentials: Credentials =
            serde_json::from_slice(&plaintext).context("Failed to deserialize credentials")?;

        Ok(credentials.api_key)
    }

    fn delete_from_file(&self) -> Result<()> {
        let file_path = self.data_dir.join(ENCRYPTED_FILE_NAME);

        if file_path.exists() {
            fs::remove_file(&file_path)
                .with_context(|| format!("Failed to delete credentials file: {:?}", file_path))?;
        }

        Ok(())
    }
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new().expect("Failed to create credential manager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_manager() -> (CredentialManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let manager = CredentialManager {
            data_dir: temp_dir.path().to_path_buf(),
            keyring_available: false, // Force file-based storage for tests
        };
        (manager, temp_dir)
    }

    #[test]
    fn test_store_and_retrieve() {
        let (manager, _temp) = test_manager();

        manager.store_api_key("test-key-12345").unwrap();
        let retrieved = manager.get_api_key().unwrap();

        assert_eq!(retrieved, Some("test-key-12345".to_string()));
    }

    #[test]
    fn test_delete() {
        let (manager, _temp) = test_manager();

        manager.store_api_key("test-key").unwrap();
        assert!(manager.has_credentials());

        manager.delete_api_key().unwrap();
        assert!(!manager.has_credentials());
    }

    #[test]
    fn test_no_credentials() {
        let (manager, _temp) = test_manager();
        assert_eq!(manager.get_api_key().unwrap(), None);
    }
}
