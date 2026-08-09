use std::collections::BTreeMap;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct MasterKey {
    pub version: u32,
    key: Zeroizing<[u8; 32]>,
}

impl MasterKey {
    pub fn new(version: u32, key: [u8; 32]) -> Result<Self, VaultError> {
        if version == 0 {
            return Err(VaultError::InvalidKeyVersion);
        }
        Ok(Self {
            version,
            key: Zeroizing::new(key),
        })
    }

    fn cipher(&self) -> Result<Aes256Gcm, VaultError> {
        Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| VaultError::InvalidMasterKey)
    }
}

#[derive(Default)]
pub struct KeyRing {
    keys: BTreeMap<u32, MasterKey>,
    current_version: Option<u32>,
}

impl KeyRing {
    pub fn insert(&mut self, key: MasterKey, make_current: bool) {
        if make_current {
            self.current_version = Some(key.version);
        }
        self.keys.insert(key.version, key);
    }

    pub fn current(&self) -> Result<&MasterKey, VaultError> {
        let version = self.current_version.ok_or(VaultError::NoCurrentMasterKey)?;
        self.keys.get(&version).ok_or(VaultError::MissingMasterKey(version))
    }

    pub fn get(&self, version: u32) -> Result<&MasterKey, VaultError> {
        self.keys
            .get(&version)
            .ok_or(VaultError::MissingMasterKey(version))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedSecret {
    pub key_version: u32,
    pub wrapped_dek_nonce: [u8; 12],
    pub wrapped_dek: Vec<u8>,
    pub data_nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub aad_hash: [u8; 32],
}

impl EncryptedSecret {
    pub fn encrypt(plaintext: &[u8], aad: &[u8], key: &MasterKey) -> Result<Self, VaultError> {
        let mut dek = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(dek.as_mut());

        let mut data_nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut data_nonce);
        let data_cipher = Aes256Gcm::new_from_slice(dek.as_ref())
            .map_err(|_| VaultError::InvalidDataKey)?;
        let ciphertext = data_cipher
            .encrypt(
                Nonce::from_slice(&data_nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| VaultError::EncryptionFailed)?;

        let mut wrapped_dek_nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut wrapped_dek_nonce);
        let wrapping_aad = wrapping_aad(aad);
        let wrapped_dek = key
            .cipher()?
            .encrypt(
                Nonce::from_slice(&wrapped_dek_nonce),
                Payload {
                    msg: dek.as_ref(),
                    aad: &wrapping_aad,
                },
            )
            .map_err(|_| VaultError::EncryptionFailed)?;

        Ok(Self {
            key_version: key.version,
            wrapped_dek_nonce,
            wrapped_dek,
            data_nonce,
            ciphertext,
            aad_hash: hash(aad),
        })
    }

    pub fn decrypt(&self, aad: &[u8], keys: &KeyRing) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if self.aad_hash != hash(aad) {
            return Err(VaultError::AssociatedDataMismatch);
        }
        let master = keys.get(self.key_version)?;
        let wrapping_aad = wrapping_aad(aad);
        let dek = Zeroizing::new(
            master
                .cipher()?
                .decrypt(
                    Nonce::from_slice(&self.wrapped_dek_nonce),
                    Payload {
                        msg: &self.wrapped_dek,
                        aad: &wrapping_aad,
                    },
                )
                .map_err(|_| VaultError::DecryptionFailed)?,
        );
        let cipher = Aes256Gcm::new_from_slice(dek.as_ref())
            .map_err(|_| VaultError::InvalidDataKey)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&self.data_nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad,
                },
            )
            .map_err(|_| VaultError::DecryptionFailed)?;
        Ok(Zeroizing::new(plaintext))
    }

    pub fn rotate(&self, aad: &[u8], keys: &KeyRing) -> Result<Self, VaultError> {
        let plaintext = self.decrypt(aad, keys)?;
        Self::encrypt(plaintext.as_ref(), aad, keys.current()?)
    }
}

fn wrapping_aad(aad: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(14 + aad.len());
    value.extend_from_slice(b"snm:vault:dek:");
    value.extend_from_slice(aad);
    value
}

fn hash(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("master key version must be greater than zero")]
    InvalidKeyVersion,
    #[error("master key has invalid size")]
    InvalidMasterKey,
    #[error("data key has invalid size")]
    InvalidDataKey,
    #[error("no current master key configured")]
    NoCurrentMasterKey,
    #[error("master key version {0} is unavailable")]
    MissingMasterKey(u32),
    #[error("associated data does not match encrypted secret")]
    AssociatedDataMismatch,
    #[error("secret encryption failed")]
    EncryptionFailed,
    #[error("secret decryption failed")]
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(version: u32, byte: u8) -> MasterKey {
        MasterKey::new(version, [byte; 32]).unwrap()
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext_and_round_trips() {
        let aad = b"organization/site/credential-profile";
        let plaintext = b"SNM-SENTINEL-SECRET-DO-NOT-LEAK";
        let encrypted = EncryptedSecret::encrypt(plaintext, aad, &key(1, 7)).unwrap();
        assert!(!encrypted
            .ciphertext
            .windows(plaintext.len())
            .any(|window| window == plaintext));

        let mut ring = KeyRing::default();
        ring.insert(key(1, 7), true);
        let decrypted = encrypted.decrypt(aad, &ring).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn key_rotation_reencrypts_with_current_key() {
        let aad = b"credential/123";
        let encrypted = EncryptedSecret::encrypt(b"secret", aad, &key(1, 11)).unwrap();
        let mut ring = KeyRing::default();
        ring.insert(key(1, 11), false);
        ring.insert(key(2, 22), true);

        let rotated = encrypted.rotate(aad, &ring).unwrap();
        assert_eq!(rotated.key_version, 2);
        assert_eq!(rotated.decrypt(aad, &ring).unwrap().as_slice(), b"secret");
    }

    #[test]
    fn associated_data_prevents_cross_scope_decryption() {
        let encrypted = EncryptedSecret::encrypt(b"secret", b"site-a", &key(1, 9)).unwrap();
        let mut ring = KeyRing::default();
        ring.insert(key(1, 9), true);
        assert_eq!(
            encrypted.decrypt(b"site-b", &ring).unwrap_err(),
            VaultError::AssociatedDataMismatch
        );
    }
}
