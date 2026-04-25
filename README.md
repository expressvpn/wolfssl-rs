# WolfSSL (Rust)

This repository attempts to build safe and idiomatic abstractions for the [WolfSSL Embedded SSL/TLS Library (C)][wolfssl-home].

There are two parts to this:

- The [`wolfssl-sys`][] crate auto-generates unsafe Rust bindings through [bindgen], to C functions provided by the WolfSSL library.
- The [`wolfssl`][] crate then build safe and idiomatic abstractions on top of the unsafe layer.

[wolfssl-home]: https://www.wolfssl.com/
[`wolfssl-sys`]: ./wolfssl-sys
[`wolfssl`]: ./wolfssl
[bindgen]: https://github.com/rust-lang/rust-bindgen/

## Why WolfSSL?

At [ExpressVPN](https://www.expressvpn.com) we love [WolfSSL](https://www.wolfssl.com). It's fast, secure, easy to use and of course it's Open Source. That's why when we were looking at TLS libraries to use as the core of [Lightway](https://www.lightway.com), WolfSSL was a clear winner. Now that we're doing more research with Rust, it's only natural that we'd want to keep using WolfSSL, but alas, there weren't any Rust bindings available.

So we built one :)

# Building and Running

After cloning this repo, you'll also need to clone the submodules for the WolfSSL source code via:
```
git submodule update --init
```

The project requires `cmake`, `automake` and `autoconf` to build. Use the following command to install the dependencies on macOS:
```
brew install cmake autoconf automake
```

Currently, the usual commands from `cargo` works perfectly fine. Common commands
include the following:

```
cargo build
```

```
cargo test
```

```
cargo clippy
```

## Building with Earthly
There is also an `Earthfile` provided.  For example, here's how you can build the crate in [Earthly](https://earthly.dev):

```
earthly +build-crate
```

For more information about the different Earthly targets available, run:
```
earthly doc
```

## Semantic Versioning Guidelines

We follow [Semantic Versioning 2.0.0](https://semver.org/) for version management. Version numbers follow the format `MAJOR.MINOR.PATCH`:

- **PATCH (x.y.Z)**: Dependency updates
- **MINOR (x.Y.0)**: Backwards-compatible API changes
- **MAJOR (X.0.0)**: Backwards-incompatible changes and/or WolfSSL library version upgrades

## Releasing crate(s)

This repository is a monorepo for two crates: `wolfssl-sys` and `wolfssl`. Both crates can be released from a single PR — the release workflow publishes them sequentially (`wolfssl-sys` first, then `wolfssl`), waiting for each to appear on crates.io before proceeding.

A GitHub Workflow automates publishing to crates.io and creating GitHub releases/tags.

To release, follow these steps:

1. If `wolfssl-sys` has changes, bump the version in `wolfssl-sys/Cargo.toml`
1. If you bumped `wolfssl-sys`, update the `wolfssl-sys = { ..., version = "..." }` dependency in `wolfssl/Cargo.toml` to match
1. Bump the version in `wolfssl/Cargo.toml`
1. Open a PR — the workflow runs in dry-run mode and posts a comment showing the release plan
1. Merge the PR — the workflow publishes `wolfssl-sys` first (if needed), polls crates.io until it’s live, then publishes `wolfssl`

The workflow is idempotent: if a run fails partway through, re-running it will skip already-published crates and pick up where it left off.

Use the `ignore-release` label only on chore/CI-only PRs with no code changes. For any functional change, we expect a release unless there’s a strong reason not to. If no version bump is present and no `ignore-release` label is set, CI will block the release workflow.
