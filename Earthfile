VERSION 0.7
# Importing https://github.com/earthly/lib/tree/2.2.1/rust via commit hash pinning becuase git tags can be changed
IMPORT github.com/earthly/lib/rust:794f789da87fc638cd322e9b60f82ad896282fb3 AS rust-udc

FROM rust:1.72.1

WORKDIR /wolfssl-rs

build-deps:
    RUN apt-get update -qq
    RUN apt-get install --no-install-recommends -qq autoconf autotools-dev libtool-bin clang cmake bsdmainutils
    RUN cargo install --locked cargo-deny cargo-llvm-cov
    RUN rustup component add clippy
    RUN rustup component add rustfmt
    RUN rustup component add llvm-tools-preview

copy-src:
    FROM +build-deps
    COPY --dir Cargo.toml Cargo.lock deny.toml wolfssl wolfssl-sys ./

build-dev:
    FROM +copy-src
    DO rust-udc+CARGO --args="build"
    SAVE ARTIFACT target/debug /debug AS LOCAL artifacts/debug

build-release:
    FROM +copy-src
    DO rust-udc+CARGO --args="build --release"
    SAVE ARTIFACT target/release /release AS LOCAL artifacts/release

run-tests:
    FROM +copy-src
    DO rust-udc+CARGO --args="test"

run-coverage:
    FROM +copy-src
    DO rust-udc+CARGO --args="llvm-cov test"

    RUN mkdir /tmp/coverage

    DO rust-udc+CARGO --args="llvm-cov report --summary-only --output-path /tmp/coverage/summary.txt"
    DO rust-udc+CARGO --args="llvm-cov report --html --output-dir /tmp/coverage/"
    SAVE ARTIFACT /tmp/coverage/*

build:
    BUILD +run-tests
    BUILD +build-release

build-crate:
    FROM +copy-src
    DO rust-udc+CARGO --args="package"
    SAVE ARTIFACT target/package/*.crate /package/ AS LOCAL artifacts/crate/

lint:
    FROM +copy-src
    DO rust-udc+CARGO --args="clippy --all-features --all-targets -- -D warnings"

fmt:
    FROM +copy-src
    DO rust-udc+CARGO --args="fmt --check"

check-license:
    FROM +copy-src
    DO rust-udc+CARGO --args="deny --all-features check bans license sources"
