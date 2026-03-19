//! Helpers for implementing the Secret Storage mechanism.

use std::collections::HashMap;

use matrix_sdk_common::ruma::events::{
    secret::request::SecretName, secret_storage::key::SecretStorageKeyEventContent,
    EventContentFromType,
};
use matrix_sdk_crypto::secret_storage;
use napi_derive::napi;

use crate::into_err;

/// A key for encrypting/decrypting data in secret storage
#[napi]
#[derive(Debug)]
pub struct SecretStorageKey {
    pub(crate) inner: secret_storage::SecretStorageKey,
}

#[napi]
#[derive(Debug)]
pub struct AesHmacSha2EncryptedData {
    pub(crate) inner: secret_storage::AesHmacSha2EncryptedData,
}

#[napi]
impl SecretStorageKey {
    /// Create a new random [`SecretStorageKey`].
    #[napi]
    pub fn create_random_key() -> Self {
        Self { inner: secret_storage::SecretStorageKey::new() }
    }

    /// Create a new passphrase-based [`SecretStorageKey`]
    #[napi]
    pub fn create_from_passphrase(passphrase: String) -> Self {
        Self { inner: secret_storage::SecretStorageKey::new_from_passphrase(&passphrase) }
    }

    /// Restore a [`SecretStorageKey`] from the given input and the description
    /// of the key.
    ///
    /// The [`SecretStorageKeyEventContent`] will contain the description of the
    /// [`SecretStorageKey`]. The constructor will check if the provided input
    /// string matches to the description.
    ///
    /// The input can be a passphrase or a Base58 export of the
    /// [`SecretStorageKey`].
    #[napi]
    pub fn from_account_data(
        input: String,
        event_type: String,
        content: String,
    ) -> napi::Result<Self> {
        let content = serde_json::from_str(content.as_ref()).map_err(into_err)?;
        let key_event_content =
            SecretStorageKeyEventContent::from_parts(&event_type, content).map_err(into_err)?;
        Ok(Self {
            inner: secret_storage::SecretStorageKey::from_account_data(&input, key_event_content)
                .map_err(into_err)?,
        })
    }

    /// `Export the [`SecretStorageKey`] as a base58-encoded string.
    #[napi]
    pub fn to_base58(&self) -> String {
        self.inner.to_base58()
    }

    /// Encrypt a secret string as a Secret Storage secret
    #[napi]
    pub fn encrypt(&self, plaintext: Vec<u8>, secret_name: String) -> AesHmacSha2EncryptedData {
        AesHmacSha2EncryptedData {
            inner: self.inner.encrypt(plaintext, &SecretName::from(secret_name)),
        }
    }

    /// Decrypt the given [`AesHmacSha2EncryptedData`]
    #[napi]
    pub fn decrypt(
        &self,
        data: &AesHmacSha2EncryptedData,
        secret_name: String,
    ) -> napi::Result<Vec<u8>> {
        self.inner.decrypt(&data.inner, &SecretName::from(secret_name)).map_err(into_err)
    }

    /// The info about the [`SecretStorageKey`], as an event content for storing
    /// in account data.
    ///
    /// Returns a JSON-encoded object
    #[napi]
    pub fn event_content(&self) -> napi::Result<String> {
        serde_json::to_string(self.inner.event_content()).map_err(into_err)
    }

    /// The unique ID of this [`SecretStorageKey`]
    #[napi]
    pub fn key_id(&self) -> String {
        self.inner.key_id().to_owned()
    }

    /// The event type of this [`SecretStorageKey`] for storing in account data.
    #[napi]
    pub fn event_type(&self) -> String {
        self.inner.event_type().to_string()
    }
}

#[napi]
/// The account data events containing the secrets, encoded as JSON
pub struct SecretStorageEvents {
    pub master_key_event: String,
    pub user_signing_key_event: String,
    pub self_signing_key_event: String,
}

#[napi]
impl SecretStorageEvents {
    #[napi(constructor)]
    pub fn new(events: HashMap<String, String>) -> napi::Result<Self> {
        Ok(SecretStorageEvents {
            master_key_event: events
                .get("masterKeyEvent")
                .ok_or(napi::Error::from_reason("missing master key"))?
                .to_string(),
            user_signing_key_event: events
                .get("userSigningKeyEvent")
                .ok_or(napi::Error::from_reason("missing user signing key"))?
                .to_string(),
            self_signing_key_event: events
                .get("selfSigningKeyEvent")
                .ok_or(napi::Error::from_reason("missing self signing key"))?
                .to_string(),
        })
    }
}
