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
There is also an `Earthfile` provided so that you can build the crate in [Earthly](https://earthly.dev):

```
earthly +build-crate
```
