use std::collections::HashMap;

use matrix_sdk_crypto::backups::{
    SignatureState as InnerSignatureState, SignatureVerification as InnerSignatureVerification,
};
use napi_derive::*;

use crate::{
    identifiers::{DeviceKeyId, UserId},
    into_err,
    vodozemac::Ed25519Signature,
};

#[napi]
#[derive(Default)]
pub struct Signatures {
    inner: matrix_sdk_crypto::types::Signatures,
}

impl From<matrix_sdk_crypto::types::Signatures> for Signatures {
    fn from(inner: matrix_sdk_crypto::types::Signatures) -> Self {
        Self { inner }
    }
}

#[napi]
impl Signatures {
    /// Creates a new, empty, signatures collection.
    #[napi(constructor)]
    pub fn new() -> Self {
        matrix_sdk_crypto::types::Signatures::new().into()
    }

    /// Add the given signature from the given signer and the given key ID to
    /// the collection.
    #[napi(strict)]
    pub fn add_signature(
        &mut self,
        signer: &UserId,
        key_id: &DeviceKeyId,
        signature: &Ed25519Signature,
    ) -> Option<MaybeSignature> {
        self.inner
            .add_signature(signer.inner.clone(), key_id.inner.clone(), signature.inner)
            .map(Into::into)
    }

    /// Try to find an Ed25519 signature from the given signer with
    /// the given key ID.
    #[napi(strict)]
    pub fn get_signature(&self, signer: &UserId, key_id: &DeviceKeyId) -> Option<Ed25519Signature> {
        self.inner.get_signature(signer.inner.as_ref(), key_id.inner.as_ref()).map(Into::into)
    }

    /// Get the map of signatures that belong to the given user.
    #[napi(strict)]
    pub fn get(&self, signer: &UserId) -> Option<HashMap<String, MaybeSignature>> {
        self.inner.get(signer.inner.as_ref()).map(|map| {
            map.iter()
                .map(|(device_key_id, maybe_signature)| {
                    (device_key_id.as_str().to_owned(), maybe_signature.clone().into())
                })
                .collect()
        })
    }

    /// Remove all the signatures we currently hold.
    #[napi]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Do we hold any signatures or is our collection completely
    /// empty.
    #[napi(getter)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// How many signatures do we currently hold.
    #[napi(getter)]
    pub fn count(&self) -> usize {
        self.inner.signature_count()
    }

    /// Get the json with all signatures
    #[napi(js_name = "asJSON")]
    pub fn as_json(&self) -> napi::Result<String> {
        Ok(serde_json::to_string(&self.inner).map_err(into_err)?.into())
    }
}

/// Represents a potentially decoded signature (but not a validated
/// one).
#[napi]
pub struct Signature {
    inner: matrix_sdk_crypto::types::Signature,
}

impl From<matrix_sdk_crypto::types::Signature> for Signature {
    fn from(inner: matrix_sdk_crypto::types::Signature) -> Self {
        Self { inner }
    }
}

#[napi]
impl Signature {
    /// Get the Ed25519 signature, if this is one.
    #[napi(getter)]
    pub fn ed25519(&self) -> Option<Ed25519Signature> {
        self.inner.ed25519().map(Into::into)
    }

    /// Convert the signature to a base64 encoded string.
    #[napi]
    pub fn to_base64(&self) -> String {
        self.inner.to_base64()
    }
}

type MaybeSignatureInner =
    Result<matrix_sdk_crypto::types::Signature, matrix_sdk_crypto::types::InvalidSignature>;

/// Represents a signature that is either valid _or_ that could not be
/// decoded.
#[napi]
pub struct MaybeSignature {
    inner: MaybeSignatureInner,
}

impl From<MaybeSignatureInner> for MaybeSignature {
    fn from(inner: MaybeSignatureInner) -> Self {
        Self { inner }
    }
}

#[napi]
impl MaybeSignature {
    /// Check whether the signature has been successfully decoded.
    #[napi(getter)]
    pub fn is_valid(&self) -> bool {
        self.inner.is_ok()
    }

    /// Check whether the signature could not be successfully decoded.
    #[napi(getter)]
    pub fn is_invalid(&self) -> bool {
        self.inner.is_err()
    }

    /// The signature, if successfully decoded.
    #[napi(getter)]
    pub fn signature(&self) -> Option<Signature> {
        self.inner.as_ref().cloned().map(Into::into).ok()
    }

    /// The base64 encoded string that is claimed to contain a
    /// signature but could not be decoded, if any.
    #[napi(getter)]
    pub fn invalid_signature_source(&self) -> Option<String> {
        match &self.inner {
            Ok(_) => None,
            Err(signature) => Some(signature.source.clone()),
        }
    }
}

/// The result of a signature verification of a signed JSON object.
#[napi]
#[derive(Debug)]
pub struct SignatureVerification {
    pub(crate) inner: InnerSignatureVerification,
}

/// The result of a signature check.
#[napi]
#[derive(Debug)]
pub enum SignatureState {
    /// The signature is missing.
    Missing = 0,
    /// The signature is invalid.
    Invalid = 1,
    /// The signature is valid but the device or user identity that created the
    /// signature is not trusted.
    ValidButNotTrusted = 2,
    /// The signature is valid and the device or user identity that created the
    /// signature is trusted.
    ValidAndTrusted = 3,
}

impl From<InnerSignatureState> for SignatureState {
    fn from(val: InnerSignatureState) -> Self {
        match val {
            InnerSignatureState::Missing => SignatureState::Missing,
            InnerSignatureState::Invalid => SignatureState::Invalid,
            InnerSignatureState::ValidButNotTrusted => SignatureState::ValidButNotTrusted,
            InnerSignatureState::ValidAndTrusted => SignatureState::ValidAndTrusted,
        }
    }
}

#[napi]
impl SignatureVerification {
    /// Give the backup signature state from the current device.
    /// See SignatureState for values
    #[napi(getter)]
    pub fn device_state(&self) -> SignatureState {
        self.inner.device_signature.into()
    }

    /// Give the backup signature state from the current user identity.
    /// See SignatureState for values
    #[napi(getter)]
    pub fn user_state(&self) -> SignatureState {
        self.inner.user_identity_signature.into()
    }

    /// Is the result considered to be trusted?
    ///
    /// This tells us if the result has a valid signature from any of the
    /// following:
    ///
    /// * Our own device
    /// * Our own user identity, provided the identity is trusted as well
    /// * Any of our own devices, provided the device is trusted as well
    #[napi]
    pub fn trusted(&self) -> bool {
        self.inner.trusted()
    }
}
