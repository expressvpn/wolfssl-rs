VERSION 0.7
FROM rust:1.72.1

WORKDIR /wolfssl-rs

build-deps:
    RUN apt-get update -qq
    RUN apt-get install --no-install-recommends -qq autoconf autotools-dev libtool-bin clang cmake bsdmainutils
    RUN rustup component add clippy
    RUN rustup component add rustfmt

copy-src:
    FROM +build-deps
    COPY --dir Cargo.toml Cargo.lock wolfssl wolfssl-sys ./

build-dev:
    FROM +copy-src
    RUN cargo build
    SAVE ARTIFACT target/debug /debug AS LOCAL artifacts/debug

build-release:
    FROM +copy-src
    RUN cargo build --release
    SAVE ARTIFACT target/release /release AS LOCAL artifacts/release

run-tests:
    FROM +copy-src
    RUN cargo test

build:
    BUILD +run-tests
    BUILD +build-release

build-crate:
    FROM +copy-src
    RUN cargo package
    SAVE ARTIFACT target/package/*.crate /package/ AS LOCAL artifacts/crate/

lint:
    FROM +copy-src
    RUN cargo clippy --all-features --all-targets -- -D warnings

fmt:
    FROM +copy-src
    RUN cargo fmt --check

check-license:
    RUN cargo install --locked cargo-deny
    COPY --dir Cargo.toml Cargo.lock deny.toml wolfssl wolfssl-sys ./
    RUN cargo deny --all-features check bans license sources
