# wolfssl-sys

Low-level unsafe bindings for [WolfSSL Embedded SSL/TLS Library (C)][wolfssl-home].

See [`wolfssl`](https://crates.io/crates/wolfssl) for safe high-level bindings.

The `benchmark` feature builds wolfSSL's wolfCrypt benchmark for
`cargo bench --features benchmark --bench wolfcrypt`. It is only meant for
development; do not enable it in dependent crates.

[wolfssl-home]: https://www.wolfssl.com/
