# wolfssl

Safe high-level bindings for [WolfSSL Embedded SSL/TLS Library (C)][wolfssl-home].

## Thread safety

By default wolfSSL is built with thread support, and `Context` can be
shared across threads.

The `singlethreaded` feature builds wolfSSL without any locking or atomics.
Only one thread may then use wolfSSL at a time. wolfSSL objects
(`ContextBuilder`, `Context`, `Session`, `Random`, `Aes256Gcm`,
`Chacha20Poly1305Aead`) are `!Send` and `!Sync`, so using one from another
thread is a compile error. The thread that creates a wolfSSL object owns
wolfSSL until all its objects are dropped; creating objects or calling
stateless functions (error strings) from any other thread meanwhile panics.
This fits single-threaded runtimes such as Tokio's `current_thread`. Tests
using this feature must run with `--test-threads=1`.

Cargo unifies features, so enabling `singlethreaded` anywhere in the
dependency graph applies it to every user of `wolfssl` in that build.

[wolfssl-home]: https://www.wolfssl.com/
