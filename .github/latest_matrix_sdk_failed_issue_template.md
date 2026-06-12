---
title: Building against the latest matrix-rust-sdk is failing
---
Something changed in [matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk)'s crypto crate that will break the build of this repo ({{ env.REPO_NAME }}) when we update to it.
