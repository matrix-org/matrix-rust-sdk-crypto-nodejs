//! Helpers for implementing the Secret Storage mechanism.

use std::collections::{BTreeMap, HashMap};

use matrix_sdk_common::ruma::{
    events::{
        secret::request::SecretName,
        secret_storage::{
            key::SecretStorageKeyEventContent,
            secret::{SecretEncryptedData, SecretEventContent},
        },
        EventContentFromType,
    },
    serde::Raw,
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
impl SecretStorageKey {
    /// Create a new random [`SecretStorageKey`].
    #[napi]
    pub fn create_random_key() -> Self {
        Self { inner: secret_storage::SecretStorageKey::new() }
    }

    /// Create a new passphrase-based [`SecretStorageKey`].
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

    /// Export the [`SecretStorageKey`] as a base58-encoded string.
    #[napi]
    pub fn to_base58(&self) -> String {
        self.inner.to_base58()
    }

    /// Encrypt a secret string as a Secret Storage secret.
    ///
    /// Returns the JSON-encoded contents to store in Account Data.
    #[napi(js_name = "encrypt")]
    pub fn encrypt_with_string_name(
        &self,
        plaintext: String,
        secret_name: String,
    ) -> napi::Result<String> {
        self.encrypt(plaintext, &SecretName::from(secret_name))
    }

    /// Encrypt a secret string as a Secret Storage secret.
    ///
    /// Returns the JSON-encoded contents to store in Account Data.
    ///
    /// This is the same as `encrypt_with_string_name`, but takes the Rust
    /// version of the `secret_name`.
    pub(crate) fn encrypt(
        &self,
        plaintext: String,
        secret_name: &SecretName,
    ) -> napi::Result<String> {
        let plaintext_string = plaintext.into_bytes();
        let encrypted_data = self.inner.encrypt(plaintext_string, secret_name);
        let encrypted_data =
            Raw::new(&encrypted_data).expect("We should be able to serialize our encrypted data");
        let mut encrypted = BTreeMap::new();
        encrypted.insert(self.key_id(), SecretEncryptedData::new(encrypted_data));
        serde_json::to_string(&SecretEventContent::new(encrypted)).map_err(into_err)
    }

    /// Decrypt the given Secret Storage item, given as the JSON-encoded
    /// contents.
    #[napi(js_name = "decrypt")]
    pub fn decrypt_with_string_name(
        &self,
        account_data_content_json: String,
        secret_name: String,
    ) -> napi::Result<String> {
        self.decrypt(&account_data_content_json, &SecretName::from(secret_name))
    }

    /// Decrypt the given Secret Storage item, given as the JSON-encoded
    /// contents.
    ///
    /// This is the same as `decrypt_with_string_name`, but takes the Rust
    /// version of the `secret_name`.
    pub(crate) fn decrypt(
        &self,
        account_data_content_json: &str,
        secret_name: &SecretName,
    ) -> napi::Result<String> {
        let mut content: SecretEventContent =
            serde_json::from_str(account_data_content_json).map_err(into_err)?;
        let secret_data = content
            .encrypted
            .remove(self.inner.key_id())
            .ok_or(napi::Error::from_reason(format!("{secret_name} not encrypted with key")))?;

        let secret_data = secret_data.deserialize_as().map_err(into_err)?;
        let secret = self.inner.decrypt(&secret_data, secret_name).map_err(into_err)?;

        String::from_utf8(secret).map_err(into_err)
    }

    /// The info about the [`SecretStorageKey`], as an item for storing in
    /// account data.
    ///
    /// Returns a JSON-encoded object.
    #[napi]
    pub fn account_data_content(&self) -> napi::Result<String> {
        serde_json::to_string(self.inner.event_content()).map_err(into_err)
    }

    /// The unique ID of this [`SecretStorageKey`].
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
/// The account data items containing the secrets, encoded as JSON
pub struct SecretStorageItems {
    pub master_key: String,
    pub user_signing_key: String,
    pub self_signing_key: String,
}

#[napi]
impl SecretStorageItems {
    #[napi(constructor)]
    pub fn new(items: HashMap<String, String>) -> napi::Result<Self> {
        Ok(SecretStorageItems {
            master_key: items
                .get("masterKey")
                .ok_or(napi::Error::from_reason("missing master key"))?
                .to_string(),
            user_signing_key: items
                .get("userSigningKey")
                .ok_or(napi::Error::from_reason("missing user signing key"))?
                .to_string(),
            self_signing_key: items
                .get("selfSigningKey")
                .ok_or(napi::Error::from_reason("missing self signing key"))?
                .to_string(),
        })
    }
}
