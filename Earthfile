VERSION 0.8
# Importing https://github.com/earthly/lib/tree/3.0.1/rust via commit hash pinning because git tags can be changed
IMPORT github.com/earthly/lib/rust:1a4a008e271c7a5583e7bd405da8fd3624c05610 AS lib-rust

# Update RUST_VERSION in github action to the same version for building iOS/tvOS
FROM rust:1.85.0

WORKDIR /wolfssl-rs

build-deps:
    RUN apt-get update -qq
    RUN apt-get install --no-install-recommends -qq autoconf autotools-dev libtool-bin clang cmake bsdmainutils openjdk-17-jdk gcc-multilib
    DO lib-rust+INIT --keep_fingerprints=true
    DO lib-rust+CARGO --args="install --locked cargo-deny cargo-llvm-cov cargo-ndk"
    RUN rustup component add clippy
    RUN rustup component add rustfmt
    RUN rustup component add llvm-tools-preview

    ARG ANDROID_HOME=/opt/android/
    ARG ANDROID_NDK_VERSION=27.0.12077973

    # Install android targets
    RUN rustup target add aarch64-linux-android
    RUN rustup target add armv7-linux-androideabi
    RUN rustup target add i686-linux-android
    RUN rustup target add x86_64-linux-android

    RUN mkdir -p ${ANDROID_HOME}/cmdline-tools \
     && wget -q 'https://dl.google.com/android/repository/commandlinetools-linux-6200805_latest.zip' -P /tmp  \
     && unzip -q -d ${ANDROID_HOME}/cmdline-tools /tmp/commandlinetools-linux-6200805_latest.zip \
     && yes Y | ${ANDROID_HOME}/cmdline-tools/tools/bin/sdkmanager --install "ndk;${ANDROID_NDK_VERSION}" \
     && yes Y | ${ANDROID_HOME}/cmdline-tools/tools/bin/sdkmanager --licenses

    ENV ANDROID_NDK_HOME=${ANDROID_HOME}/ndk/${ANDROID_NDK_VERSION}

copy-src:
    FROM +build-deps
    COPY --keep-ts --dir Cargo.toml Cargo.lock deny.toml wolfssl wolfssl-sys ./

# build-dev builds with the Cargo dev profile and produces debug artifacts
build-dev:
    FROM +copy-src
    DO lib-rust+CARGO --args="build" --output="debug/[^/]+"
    SAVE ARTIFACT target/debug /debug AS LOCAL artifacts/debug

# build-release builds with the Cargo release profile and produces release artifacts
build-release:
    FROM +copy-src
    DO lib-rust+CARGO --args="build --release" --output="release/[^/]+"
    SAVE ARTIFACT target/release /release AS LOCAL artifacts/release

# run-tests executes all unit and integration tests via Cargo
run-tests:
    FROM +copy-src
    DO lib-rust+CARGO --args="test"

# run-coverage generates a report of code coverage by unit and integration tests via cargo-llvm-cov
run-coverage:
    FROM +copy-src

    RUN mkdir /tmp/coverage

    DO lib-rust+SET_CACHE_MOUNTS_ENV
    RUN --mount=$EARTHLY_RUST_CARGO_HOME_CACHE --mount=$EARTHLY_RUST_TARGET_CACHE \
        cargo llvm-cov test && \
        cargo llvm-cov report --summary-only --output-path /tmp/coverage/summary.txt && \
        cargo llvm-cov report --json --output-path /tmp/coverage/coverage.json && \
        cargo llvm-cov report --html --output-dir /tmp/coverage/

    SAVE ARTIFACT /tmp/coverage/*

# build runs tests and then creates a release build
build:
    BUILD +run-tests
    BUILD +build-release

# build-crate creates a .crate file for distribution of source code
build-crate:
    FROM +copy-src
    DO lib-rust+CARGO --args="package" --output="package/.*\.crate"
    SAVE ARTIFACT target/package/*.crate /package/ AS LOCAL artifacts/crate/

build-android-release:
    FROM +copy-src
    DO lib-rust+CARGO --args="ndk -t x86_64 -t x86 -t armeabi-v7a -t arm64-v8a build --release -vv" --output="release/[^/]+"

# lint runs cargo clippy on the source code
lint:
    FROM +copy-src
    DO lib-rust+CARGO --args="clippy --all-features --all-targets -- -D warnings"
    DO lib-rust+CARGO --args="clippy --no-default-features --all-targets -- -D warnings"
    ENV RUSTDOCFLAGS="-D warnings"
    DO lib-rust+CARGO --args="doc --all-features --document-private-items"

# fmt checks whether Rust code is formatted according to style guidelines
fmt:
    FROM +copy-src
    DO lib-rust+CARGO --args="fmt --check"

# check-dependencies lints our dependencies via cargo-deny
check-dependencies:
    FROM +copy-src
    DO lib-rust+CARGO --args="deny --all-features check --deny warnings bans license sources"

# publish publishes the target crate to cargo.io. Must specify package by --PACKAGE=<package-name>
publish:
    FROM +copy-src
    ARG --required PACKAGE
    ARG DRY_RUN=true

    LET DRY_RUN_OPTION=""
    IF [ "$DRY_RUN" = "true" ]
        SET DRY_RUN_OPTION="--dry-run"
    END

    # earthly doesn't support passing secrets to FUNCTION directly. Calling the cargo command directly instead.
    RUN --push --secret CARGO_REGISTRY_TOKEN cargo publish --package $PACKAGE $DRY_RUN_OPTION
