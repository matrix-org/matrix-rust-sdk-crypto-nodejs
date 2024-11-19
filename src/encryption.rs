use std::time::Duration;

use matrix_sdk_common::deserialized_responses::{
    ShieldState as RustShieldState, ShieldStateCode as RustShieldStateCode,
};
use matrix_sdk_crypto::CollectStrategy;
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

    /// Should untrusted devices receive the room key, or should they be
    /// excluded from the conversation.
    pub only_allow_trusted_devices: bool,

    /// Should we bleh?
    pub error_on_verified_user_problem: bool,
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
            only_allow_trusted_devices: false,
            error_on_verified_user_problem: false,
        }
    }
}

impl From<&EncryptionSettings> for matrix_sdk_crypto::olm::EncryptionSettings {
    fn from(value: &EncryptionSettings) -> Self {
        Self {
            algorithm: value.algorithm.into(),
            rotation_period: Duration::from_micros(value.rotation_period.get_u64().1),
            rotation_period_msgs: value.rotation_period_messages.get_u64().1,
            history_visibility: value.history_visibility.into(),
            sharing_strategy: CollectStrategy::DeviceBasedStrategy {
                only_allow_trusted_devices: value.only_allow_trusted_devices,
                error_on_verified_user_problem: value.error_on_verified_user_problem,
            },
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
    /// An unencrypted event in an encrypted room.
    SentInClear,
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
            RustShieldStateCode::SentInClear => ShieldStateCode::SentInClear,
            RustShieldStateCode::VerificationViolation => ShieldStateCode::VerificationViolation,
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
