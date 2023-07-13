//! Megolm backup types

use std::{collections::HashMap, iter, ops::DerefMut};

use hmac::Hmac;
use matrix_sdk_crypto::{backups::MegolmV1BackupKey as InnerMegolmV1BackupKey, store::RecoveryKey};
use napi_derive::*;
use pbkdf2::pbkdf2;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::into_err;

/// The private part of the backup key, the one used for recovery.
#[napi]
pub struct BackupRecoveryKey {
    pub(crate) inner: RecoveryKey,
    pub(crate) passphrase_info: Option<PassphraseInfo>,
}

/// Struct containing info about the way the backup key got derived from a
/// passphrase.
#[napi]
#[derive(Clone)]
pub struct PassphraseInfo {
    /// The salt that was used during key derivation.
    #[napi(getter)]
    pub private_key_salt: String,
    /// The number of PBKDF rounds that were used for key derivation.
    pub private_key_iterations: i32,
}

/// The public part of the backup key.
#[napi]
#[derive(Clone)]
pub struct MegolmV1BackupKey {
    inner: InnerMegolmV1BackupKey,
    passphrase_info: Option<PassphraseInfo>,
}

#[napi]
impl MegolmV1BackupKey {
    /// The actual base64 encoded public key.
    #[napi(getter, js_name = "publicKeyBase64")]
    pub fn public_key(&self) -> String {
        self.inner.to_base64().into()
    }

    /// The passphrase info, if the key was derived from one.
    #[napi(getter)]
    pub fn passphrase_info(&self) -> Option<PassphraseInfo> {
        self.passphrase_info.clone()
    }

    /// Get the full name of the backup algorithm this backup key supports.
    #[napi(getter, js_name = "algorithm")]
    pub fn backup_algorithm(&self) -> String {
        self.inner.backup_algorithm().into()
    }

    /// Signatures that have signed our backup key.
    /// map of userId to map of deviceOrKeyId to signature
    #[napi(getter)]
    pub fn signatures(&self) -> HashMap<String, HashMap<String, String>> {
        self
            .inner
            .signatures()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into_iter().map(|(k, v)| (k.to_string(), v)).collect()))
            .collect()
    }
}

impl BackupRecoveryKey {
    const KEY_SIZE: usize = 32;
    const SALT_SIZE: usize = 32;
    const PBKDF_ROUNDS: i32 = 500_000;
}

#[napi]
impl BackupRecoveryKey {
    /// Create a new random [`BackupRecoveryKey`].
    #[napi]
    pub fn create_random_key() -> BackupRecoveryKey {
        BackupRecoveryKey {
            inner: RecoveryKey::new()
                .expect("Can't gather enough randomness to create a recovery key"),
            passphrase_info: None,
        }
    }

    /// Try to create a [`BackupRecoveryKey`] from a base 64 encoded string.
    #[napi]
    pub fn from_base64(key: String) -> napi::Result<BackupRecoveryKey> {
        Ok(Self { inner: RecoveryKey::from_base64(&key).map_err(into_err)?, passphrase_info: None })
    }

    /// Try to create a [`BackupRecoveryKey`] from a base 58 encoded string.
    #[napi]
    pub fn from_base58(key: String) -> napi::Result<BackupRecoveryKey> {
        Ok(Self { inner: RecoveryKey::from_base58(&key).map_err(into_err)?, passphrase_info: None })
    }

    /// Create a new [`BackupRecoveryKey`] from the given passphrase.
    #[napi]
    pub fn new_from_passphrase(passphrase: String) -> BackupRecoveryKey {
        let mut rng = thread_rng();
        let salt: String = iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(Self::SALT_SIZE)
            .collect();

        BackupRecoveryKey::from_passphrase(passphrase, salt, Self::PBKDF_ROUNDS)
    }

    /// Restore a [`BackupRecoveryKey`] from the given passphrase.
    #[napi]
    pub fn from_passphrase(passphrase: String, salt: String, rounds: i32) -> Self {
        let mut key = Box::new([0u8; Self::KEY_SIZE]);
        let rounds = rounds as u32;

        pbkdf2::<Hmac<Sha512>>(passphrase.as_bytes(), salt.as_bytes(), rounds, key.deref_mut());

        let recovery_key = RecoveryKey::from_bytes(&key);

        key.zeroize();

        Self {
            inner: recovery_key,
            passphrase_info: Some(PassphraseInfo {
                private_key_salt: salt.into(),
                private_key_iterations: rounds as i32,
            }),
        }
    }

    /// Convert the recovery key to a base 58 encoded string.
    #[napi]
    pub fn to_base58(&self) -> String {
        self.inner.to_base58().into()
    }

    /// Convert the recovery key to a base 64 encoded string.
    #[napi]
    pub fn to_base64(&self) -> String {
        self.inner.to_base64().into()
    }

    /// Get the public part of the backup key.
    #[napi(getter)]
    pub fn megolm_v1_public_key(&self) -> MegolmV1BackupKey {
        let public_key = self.inner.megolm_v1_public_key();

        MegolmV1BackupKey { inner: public_key, passphrase_info: self.passphrase_info.clone() }
    }

    /// Try to decrypt a message that was encrypted using the public part of the
    /// backup key.
    #[napi]
    pub fn decrypt_v1(
        &self,
        ephemeral_key: String,
        mac: String,
        ciphertext: String,
    ) -> napi::Result<String> {
        self.inner
            .decrypt_v1(&ephemeral_key, &mac, &ciphertext)
            .map_err(into_err)
    }
}
