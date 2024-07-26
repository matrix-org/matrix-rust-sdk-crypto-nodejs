//! Megolm backup types

use matrix_sdk_crypto::{
    backups::MegolmV1BackupKey as InnerMegolmV1BackupKey, olm::InboundGroupSession, store,
};
use napi_derive::*;

use crate::into_err;

/// The private part of the backup key, the one used for recovery.
#[napi]
#[derive(Debug)]
pub struct BackupDecryptionKey {
    pub(crate) inner: store::BackupDecryptionKey,
}

/// The public part of the backup key.
#[napi]
#[derive(Debug, Clone)]
pub struct MegolmV1BackupKey {
    inner: InnerMegolmV1BackupKey,
}

#[napi(object)]
#[derive(Debug, Clone)]
pub struct SessionData {
    /// Unpadded base64-encoded public half of the ephemeral key.
    pub ephemeral: String,

    /// Ciphertext, encrypted using AES-CBC-256 with PKCS#7 padding, encoded in
    /// base64.
    pub ciphertext: String,

    /// First 8 bytes of MAC key, encoded in base64.
    pub mac: String,
}

#[napi]
#[derive(Debug, Clone)]
pub struct KeyBackupData {
    pub first_message_index: i64,
    pub forwarded_count: i64,
    pub is_verified: bool,
    pub session_data: SessionData,
}

#[napi]
impl MegolmV1BackupKey {
    /// The actual base64 encoded public key.
    #[napi(getter, js_name = "publicKeyBase64")]
    pub fn public_key(&self) -> String {
        self.inner.to_base64().into()
    }

    /// Get the full name of the backup algorithm this backup key supports.
    #[napi(getter, js_name = "algorithm")]
    pub fn backup_algorithm(&self) -> String {
        self.inner.backup_algorithm().into()
    }

    /// Try to create a [`MegolmV1BackupKey`] from a base 64 encoded string.
    #[napi(strict)]
    pub fn from_base64(key: String) -> napi::Result<MegolmV1BackupKey> {
        Ok(Self { inner: InnerMegolmV1BackupKey::from_base64(&key).map_err(into_err)? })
    }

    /// Encrypt an exported room session which can then be uploaded to the
    /// homeserver's key backup. Consumes a single session exported from
    /// `OlmMachine.export_room_keys_for_session`
    #[napi(strict)]
    pub async fn encrypt_exported_session(
        &self,
        exported_session_json: String,
    ) -> napi::Result<KeyBackupData> {
        let exported_session = serde_json::from_str(&exported_session_json).map_err(into_err)?;
        let session = InboundGroupSession::from_export(&exported_session).map_err(into_err)?;
        let res = self.inner.encrypt(session).await;
        Ok(KeyBackupData {
            first_message_index: res.first_message_index.into(),
            forwarded_count: res.forwarded_count.into(),
            is_verified: res.is_verified,
            session_data: SessionData {
                ephemeral: res.session_data.ephemeral.to_string(),
                ciphertext: res.session_data.ciphertext.to_string(),
                mac: res.session_data.mac.to_string(),
            },
        })
    }
}

#[napi]
impl BackupDecryptionKey {
    /// Create a new random [`BackupDecryptionKey`].
    #[napi]
    pub fn create_random_key() -> BackupDecryptionKey {
        BackupDecryptionKey {
            inner: store::BackupDecryptionKey::new()
                .expect("Can't gather enough randomness to create a recovery key"),
        }
    }

    /// Try to create a [`BackupDecryptionKey`] from a base 64 encoded string.
    #[napi(strict)]
    pub fn from_base64(key: String) -> napi::Result<BackupDecryptionKey> {
        Ok(Self { inner: store::BackupDecryptionKey::from_base64(&key).map_err(into_err)? })
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

        MegolmV1BackupKey { inner: public_key }
    }

    /// Try to decrypt a message that was encrypted using the public part of the
    /// backup key.
    #[napi(strict)]
    pub fn decrypt_v1(
        &self,
        ephemeral_key: String,
        mac: String,
        ciphertext: String,
    ) -> napi::Result<String> {
        self.inner.decrypt_v1(&ephemeral_key, &mac, &ciphertext).map_err(into_err)
    }
}

/// Struct holding the number of room keys we have.
#[napi]
#[derive(Debug)]
pub struct RoomKeyCounts {
    /// The total number of room keys.
    pub total: f64,
    /// The number of backed up room keys.
    pub backed_up: f64,
}

impl From<matrix_sdk_crypto::store::RoomKeyCounts> for RoomKeyCounts {
    fn from(inner: matrix_sdk_crypto::store::RoomKeyCounts) -> Self {
        RoomKeyCounts {
            // There is no `TryFrom<usize> for f64`, so first downcast the usizes to u32, then back
            // up to f64
            total: inner.total.try_into().unwrap_or(u32::MAX).into(),
            backed_up: inner.backed_up.try_into().unwrap_or(u32::MAX).into(),
        }
    }
}

/// Stored versions of the backup keys.
#[napi]
#[derive(Debug)]
pub struct BackupKeys {
    /// The key used to decrypt backed up room keys, encoded as base64
    #[napi(getter)]
    pub decryption_key_base64: Option<String>,
    /// The version that we are using for backups.
    #[napi(getter)]
    pub backup_version: Option<String>,
}
