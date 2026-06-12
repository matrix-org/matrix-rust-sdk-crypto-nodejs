//! Information about a device

use napi_derive::napi;

/// A device represents a E2EE capable client of an user.
#[napi]
pub struct Device {
    pub(crate) inner: matrix_sdk_crypto::Device,
}

#[napi]
impl Device {
    /// Is this device considered to be verified.
    ///
    /// This method returns true if either the `is_locally_trusted`
    /// method returns `true` or if the `is_cross_signing_trusted`
    /// method returns `true`.
    #[napi]
    pub fn is_verified(&self) -> bool {
        self.inner.is_verified()
    }

    /// Is this device considered to be verified using cross signing.
    #[napi]
    pub fn is_cross_signing_trusted(&self) -> bool {
        self.inner.is_cross_signing_trusted()
    }

    /// Is this device cross-signed by its owner?
    #[napi]
    pub fn is_cross_signed_by_owner(&self) -> bool {
        self.inner.is_cross_signed_by_owner()
    }
}

impl From<matrix_sdk_crypto::Device> for Device {
    fn from(value: matrix_sdk_crypto::Device) -> Self {
        Self { inner: value }
    }
}
