# Matrix-Rust-SDK Node.js Bindings

## UNRELEASED

-   Fix malformed `/keys/upload`, `/keys/query` and `/keys/claim` requests. [#56](https://github.com/matrix-org/matrix-rust-sdk-crypto-nodejs/pull/56)

## v0.4.0-beta.1 - 2025-08-11

-   Update matrix-rust-sdk dependency to 0.9.0.
-   Support Node.JS 24, drop support for 18, 20.
-   Support Rust 1.77.
-   Minimum supported glibc version is now `2.35` (Ubuntu 22.04+ compatible). Support has been dropped for prior versions.
-   `RoomId` no longer has a `serverName` property, and is allowed to not have a server name component.
    This is a breaking change.

## 0.3.0-beta.1 - 2024-11-18

-   Update matrix-rust-sdk dependency.
-   The SignedCurve25519 algorithm is no longer supported.

## 0.2.0-beta.1 - 2024-06-11

-   Support Node.JS 22, drop support for 16, 19.
-   Update matrix-rust-sdk dependency.
-   `RoomId` no longer has a `localpart` property.

## 0.1.0-beta.12 - 2024-02-01

-   Add prebuilt library support for 390x. [#32](https://github.com/matrix-org/matrix-rust-sdk-crypto-nodejs/pull/32)

## 0.1.0-beta.11 - 2023-09-05

-   Add `export_room_keys_for_session`. [#26](https://github.com/matrix-org/matrix-rust-sdk-crypto-nodejs/pull/26)

## 0.1.0-beta.10 - 2023-08-11

-   Return `ToDeviceRequest` objects from `OlmMachine.share_room_key`. [#15](https://github.com/matrix-org/matrix-rust-sdk-crypto-nodejs/pull/15)
-   Added documentation for the release process. [#21](https://github.com/matrix-org/matrix-rust-sdk-crypto-nodejs/pull/21)

## 0.1.0-beta.9 - 2023-08-02

-   Update URL & tag in pre-built download script. [#13](https://github.com/matrix-org/matrix-rust-sdk-crypto-nodejs/pull/13)

## 0.1.0-beta.8 - 2023-08-01

-   Don't skip downloading the native library when installing from npm.

## 0.1.0-beta.7 - 2023-08-01

-   Expose bindings for secure key backup. [#7](https://github.com/matrix-org/matrix-rust-sdk-crypto-nodejs/pull/7)

## 0.1.0-beta.6 - 2023-04-26

-   Update supported Node.js versions. [#1822](https://github.com/matrix-org/matrix-rust-sdk/pull/1822)
-   Various bug fixes and improvements.

## 0.1.0-beta.5 - 2023-04-24

-   Build Node bindings against Ubuntu 20.04. [#1819](https://github.com/matrix-org/matrix-rust-sdk/pull/1819)
-   Various bug fixes and improvements.

## 0.1.0-beta.4 - 2023-04-14

-   Support a new sqlite storage type. [#1521](https://github.com/matrix-org/matrix-rust-sdk/pull/1521)
-   Various bug fixes and improvements.

## 0.1.0-beta.3 - 2022-11-03

-   [Fix the pre-built downloading script for Node.js 19.](https://github.com/matrix-org/matrix-rust-sdk/pull/1164)

## 0.1.0-beta.2 - 2022-09-28

## 0.1.0-beta.1 - 2022-07-14

-   Fixing broken download link, [#842](https://github.com/matrix-org/matrix-rust-sdk/issues/842)

## 0.1.0-beta.0 - 2022-07-12

Welcome to the first release of `matrix-sdk-crypto-nodejs`. This is a
Node.js binding for the Rust `matrix-sdk-crypto` library. This is a
no-network-IO implementation of a state machine, named `OlmMachine`,
that handles E2EE (End-to-End Encryption) for Matrix clients.

The goal of this binding is _not_ to cover the entirety of the
`matrix-sdk-crypto` API, but only what's required to build Matrix bots
or Matrix bridges (i.e. to connect different networks together via the
Matrix protocol).

This project replaces and deprecates a previous project, with the same
name and same goals, inside [the `matrix-rust-sdk-bindings`
repository](https://github.com/matrix-org/matrix-rust-sdk-bindings),
with the NPM package name `@turt2live/matrix-sdk-crypto-nodejs`. The
The new official package name is
`@matrix-org/matrix-sdk-crypto-nodejs`.

Note: All bindings are now part of [the `matrix-rust-sdk`
repository](https://github.com/matrix-org/matrix-rust-sdk) (see the
`bindings/` root directory).

[A documentation is available inside the new
`matrix-sdk-crypto-nodejs`
project](https://github.com/matrix-org/matrix-rust-sdk/tree/0bde5ccf38f8cda3865297a2d12ddcdaf4b80ca7/bindings/matrix-sdk-crypto-nodejs).
