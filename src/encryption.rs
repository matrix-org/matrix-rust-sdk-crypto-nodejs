use std::time::Duration;

use matrix_sdk_common::deserialized_responses::{
    ShieldState as RustShieldState, ShieldStateCode as RustShieldStateCode,
};
use napi::bindgen_prelude::BigInt;
use napi_derive::*;

use crate::events;

/// An encryption algorithm to be used to encrypt messages sent to a
/// room.
#[napi]
pub enum EncryptionAlgorithm {
    /// Olm version 1 using Curve25519, AES-256, and SHA-256.
    OlmV1Curve25519AesSha2,

    /// Megolm version 1 using AES-256 and SHA-256.
    MegolmV1AesSha2,
}

impl From<EncryptionAlgorithm> for matrix_sdk_crypto::types::EventEncryptionAlgorithm {
    fn from(value: EncryptionAlgorithm) -> Self {
        use EncryptionAlgorithm::*;

        match value {
            OlmV1Curve25519AesSha2 => Self::OlmV1Curve25519AesSha2,
            MegolmV1AesSha2 => Self::MegolmV1AesSha2,
        }
    }
}

impl From<matrix_sdk_crypto::types::EventEncryptionAlgorithm> for EncryptionAlgorithm {
    fn from(value: matrix_sdk_crypto::types::EventEncryptionAlgorithm) -> Self {
        use matrix_sdk_crypto::types::EventEncryptionAlgorithm::*;

        match value {
            OlmV1Curve25519AesSha2 => Self::OlmV1Curve25519AesSha2,
            MegolmV1AesSha2 => Self::MegolmV1AesSha2,
            _ => unreachable!("Unknown variant"),
        }
    }
}

/// Settings for an encrypted room.
///
/// This determines the algorithm and rotation periods of a group
/// session.
#[napi]
pub struct EncryptionSettings {
    /// The encryption algorithm that should be used in the room.
    pub algorithm: EncryptionAlgorithm,

    /// How long the session should be used before changing it,
    /// expressed in microseconds.
    pub rotation_period: BigInt,

    /// How many messages should be sent before changing the session.
    pub rotation_period_messages: BigInt,

    /// The history visibility of the room when the session was
    /// created.
    pub history_visibility: events::HistoryVisibility,

    /// The strategy used to distribute the room keys to participant.
    /// Default will send to all devices.
    pub sharing_strategy: CollectStrategy,
}

impl Default for EncryptionSettings {
    fn default() -> Self {
        let default = matrix_sdk_crypto::olm::EncryptionSettings::default();

        Self {
            algorithm: default.algorithm.into(),
            rotation_period: {
                let n: u64 = default.rotation_period.as_micros().try_into().unwrap();

                n.into()
            },
            rotation_period_messages: {
                let n = default.rotation_period_msgs;

                n.into()
            },
            history_visibility: default.history_visibility.into(),
            sharing_strategy: CollectStrategy::AllDevices,
        }
    }
}

#[napi]
impl EncryptionSettings {
    /// Create a new `EncryptionSettings` with default values.
    #[napi(constructor)]
    pub fn new() -> EncryptionSettings {
        Self::default()
    }
}

impl From<&EncryptionSettings> for matrix_sdk_crypto::olm::EncryptionSettings {
    fn from(value: &EncryptionSettings) -> Self {
        Self {
            algorithm: value.algorithm.into(),
            rotation_period: Duration::from_micros(value.rotation_period.get_u64().1),
            rotation_period_msgs: value.rotation_period_messages.get_u64().1,
            history_visibility: value.history_visibility.into(),
            sharing_strategy: value.sharing_strategy.into(),
        }
    }
}

/// Strategy to collect the devices that should receive room keys for the
/// current discussion.
#[napi]
pub enum CollectStrategy {
    /// Share with all (unblacklisted) devices.
    ///
    /// Not recommended, per the guidance of [MSC4153].
    ///
    /// (Used by Element X and Element Web in the legacy, non-"exclude insecure
    /// devices" mode.)
    ///
    /// [MSC4153]: https://github.com/matrix-org/matrix-doc/pull/4153
    AllDevices,

    /// Share with all devices, except errors for *verified* users cause sharing
    /// to fail with an error.
    ///
    /// In this strategy, if a verified user has an unsigned device,
    /// key sharing will fail with a
    /// [`SessionRecipientCollectionError::VerifiedUserHasUnsignedDevice`].
    /// If a verified user has replaced their identity, key
    /// sharing will fail with a
    /// [`SessionRecipientCollectionError::VerifiedUserChangedIdentity`].
    ///
    /// Otherwise, keys are shared with unsigned devices as normal.
    ///
    /// Once the problematic devices are blacklisted or whitelisted the
    /// caller can retry to share a second time.
    ///
    /// Not recommended, per the guidance of [MSC4153].
    ///
    /// [MSC4153]: https://github.com/matrix-org/matrix-doc/pull/4153
    ErrorOnVerifiedUserProblem,

    /// Share based on identity. Only distribute to devices signed by their
    /// owner. If a user has no published identity he will not receive
    /// any room keys.
    ///
    /// This is the recommended strategy: it is compliant with the guidance of
    /// [MSC4153].
    ///
    /// (Used by Element Web and Element X in the "exclude insecure devices"
    /// mode.)
    ///
    /// [MSC4153]: https://github.com/matrix-org/matrix-doc/pull/4153
    IdentityBasedStrategy,

    /// Only share keys with devices that we "trust". A device is trusted if any
    /// of the following is true:
    ///     - It was manually marked as trusted.
    ///     - It was marked as verified via interactive verification.
    ///     - It is signed by its owner identity, and this identity has been
    ///       trusted via interactive verification.
    ///     - It is the current own device of the user.
    ///
    /// This strategy is compliant with [MSC4153], but is probably too strict
    /// for normal use.
    ///
    /// (Used by Element Web when "only send messages to verified users" is
    /// enabled.)
    ///
    /// [MSC4153]: https://github.com/matrix-org/matrix-doc/pull/4153
    OnlyTrustedDevices,
}

impl Into<matrix_sdk_crypto::CollectStrategy> for CollectStrategy {
    fn into(self) -> matrix_sdk_crypto::CollectStrategy {
        match self {
            CollectStrategy::AllDevices => matrix_sdk_crypto::CollectStrategy::AllDevices,
            CollectStrategy::ErrorOnVerifiedUserProblem => {
                matrix_sdk_crypto::CollectStrategy::ErrorOnVerifiedUserProblem
            }
            CollectStrategy::IdentityBasedStrategy => {
                matrix_sdk_crypto::CollectStrategy::IdentityBasedStrategy
            }
            CollectStrategy::OnlyTrustedDevices => {
                matrix_sdk_crypto::CollectStrategy::OnlyTrustedDevices
            }
        }
    }
}

/// Take a look at [`matrix_sdk_common::deserialized_responses::ShieldState`]
/// for more info.
#[napi]
pub enum ShieldColor {
    Red,
    Grey,
    None,
}

/// Take a look at
/// [`matrix_sdk_common::deserialized_responses::ShieldStateCode`]
/// for more info.
#[napi]
pub enum ShieldStateCode {
    /// Not enough information available to check the authenticity.
    AuthenticityNotGuaranteed,
    /// The sending device isn't yet known by the Client.
    UnknownDevice,
    /// The sending device hasn't been verified by the sender.
    UnsignedDevice,
    /// The sender hasn't been verified by the Client's user.
    UnverifiedIdentity,
    /// The `sender` field on the event does not match the owner of the device
    /// that established the Megolm session.
    MismatchedSender,
    /// The sender was previously verified but changed their identity.
    VerificationViolation,
    None,
}

impl From<RustShieldStateCode> for ShieldStateCode {
    fn from(value: RustShieldStateCode) -> Self {
        match value {
            RustShieldStateCode::AuthenticityNotGuaranteed => {
                ShieldStateCode::AuthenticityNotGuaranteed
            }
            RustShieldStateCode::UnknownDevice => ShieldStateCode::UnknownDevice,
            RustShieldStateCode::UnsignedDevice => ShieldStateCode::UnsignedDevice,
            RustShieldStateCode::UnverifiedIdentity => ShieldStateCode::UnverifiedIdentity,
            RustShieldStateCode::VerificationViolation => ShieldStateCode::VerificationViolation,
            RustShieldStateCode::MismatchedSender => ShieldStateCode::MismatchedSender,
        }
    }
}

/// Take a look at [`matrix_sdk_common::deserialized_responses::ShieldState`]
/// for more info.
#[napi]
pub struct ShieldState {
    pub color: ShieldColor,
    pub code: ShieldStateCode,
    pub message: Option<&'static str>,
}

impl From<RustShieldState> for ShieldState {
    fn from(value: RustShieldState) -> Self {
        match value {
            RustShieldState::Red { message, code } => {
                ShieldState { color: ShieldColor::Red, message: Some(message), code: code.into() }
            }
            RustShieldState::Grey { message, code } => {
                ShieldState { color: ShieldColor::Grey, message: Some(message), code: code.into() }
            }
            RustShieldState::None => {
                ShieldState { color: ShieldColor::None, message: None, code: ShieldStateCode::None }
            }
        }
    }
}
