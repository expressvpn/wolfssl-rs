VERSION --global-cache 0.7
# Importing https://github.com/earthly/lib/tree/2.2.10/rust via commit hash pinning because git tags can be changed
IMPORT github.com/earthly/lib/rust:e38fc97bc13da7dbe1d9644641dc658701c1d98a AS rust-udc

FROM rust:1.74.0

WORKDIR /wolfssl-rs

build-deps:
    RUN apt-get update -qq
    RUN apt-get install --no-install-recommends -qq autoconf autotools-dev libtool-bin clang cmake bsdmainutils
    DO rust-udc+INIT --keep_fingerprints=true
    DO rust-udc+CARGO --args="install --locked cargo-deny cargo-llvm-cov"
    RUN rustup component add clippy
    RUN rustup component add rustfmt
    RUN rustup component add llvm-tools-preview

copy-src:
    FROM +build-deps
    COPY --keep-ts --dir Cargo.toml Cargo.lock deny.toml wolfssl wolfssl-sys ./

# build-dev builds with the Cargo dev profile and produces debug artifacts
build-dev:
    FROM +copy-src
    DO rust-udc+CARGO --args="build" --output="debug/[^/]+"
    SAVE ARTIFACT target/debug /debug AS LOCAL artifacts/debug

# build-release builds with the Cargo release profile and produces release artifacts
build-release:
    FROM +copy-src
    DO rust-udc+CARGO --args="build --release" --output="release/[^/]+"
    SAVE ARTIFACT target/release /release AS LOCAL artifacts/release

# run-tests executes all unit and integration tests via Cargo
run-tests:
    FROM +copy-src
    DO rust-udc+CARGO --args="test"

# run-coverage generates a report of code coverage by unit and integration tests via cargo-llvm-cov
run-coverage:
    FROM +copy-src

    RUN mkdir /tmp/coverage

    DO rust-udc+RUN_WITH_CACHE --command="cargo llvm-cov test &&
        cargo llvm-cov report --summary-only --output-path /tmp/coverage/summary.txt &&
        cargo llvm-cov report --json --output-path /tmp/coverage/coverage.json &&
        cargo llvm-cov report --html --output-dir /tmp/coverage/"

    SAVE ARTIFACT /tmp/coverage/*

# build runs tests and then creates a release build
build:
    BUILD +run-tests
    BUILD +build-release

# build-crate creates a .crate file for distribution of source code
build-crate:
    FROM +copy-src
    DO rust-udc+CARGO --args="package" --output="package/.*\.crate"
    SAVE ARTIFACT target/package/*.crate /package/ AS LOCAL artifacts/crate/

# lint runs cargo clippy on the source code
lint:
    FROM +copy-src
    DO rust-udc+CARGO --args="clippy --all-features --all-targets -- -D warnings"
    ENV RUSTDOCFLAGS="-D warnings"
    DO rust-udc+CARGO --args="doc --all-features --document-private-items"

# fmt checks whether Rust code is formatted according to style guidelines
fmt:
    FROM +copy-src
    DO rust-udc+CARGO --args="fmt --check"

# check-dependencies lints our dependencies via cargo-deny
check-dependencies:
    FROM +copy-src
    DO rust-udc+CARGO --args="deny --all-features check --deny warnings bans license sources"
