VERSION 0.7
IMPORT github.com/earthly/lib/rust:2.1.0 AS rust

FROM rust:1.72

WORKDIR /wolfssl

build-deps:
    RUN apt-get update -qq
    RUN apt-get install --no-install-recommends -qq autoconf autotools-dev libtool-bin clang cmake
    RUN apt-get -y install --no-install-recommends bsdmainutils
    RUN cargo install --locked cargo-deny
    RUN rustup component add rustfmt
    RUN rustup component add clippy

copy-src:
    FROM +build-deps
    COPY Cargo.toml Cargo.lock ./
    COPY deny.toml ./
    COPY --dir src tests ./

build-dev:
    FROM +copy-src
    DO rust+CARGO --args="build"
    SAVE ARTIFACT target/debug /debug AS LOCAL artifacts/debug

build-release:
    FROM +copy-src
    DO rust+CARGO --args="build --release"
    SAVE ARTIFACT target/release /release AS LOCAL artifacts/release

run-tests:
    FROM +copy-src
    DO rust+CARGO --args="test"

build:
    BUILD +run-tests
    BUILD +build-release

build-crate:
    FROM +copy-src
    DO rust+CARGO --args="package"
    SAVE ARTIFACT target/package/*.crate /package/ AS LOCAL artifacts/crate/

lint:
    FROM +copy-src
    DO rust+CARGO --args="clippy --all-features --all-targets -- -D warnings"

fmt:
    FROM +copy-src
    DO rust+CARGO --args="fmt --check"

ci:
    BUILD +run-tests
    BUILD +build-release
    BUILD +lint
    BUILD +fmt
    BUILD +check-license

check-license:
    FROM +copy-src
    DO rust+CARGO --args="deny --all-features check bans license sources"
