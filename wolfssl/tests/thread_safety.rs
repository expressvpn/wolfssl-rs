//! Sharing wolfSSL objects across threads must never be undefined behaviour.

#![deny(unsafe_code)] // unsafety should all be in the library.

use std::thread;

use wolfssl::{ContextBuilder, IOCallbackResult, IOCallbacks, Method, SessionConfig};

struct NoIo;

impl IOCallbacks for NoIo {
    fn recv(&mut self, _buf: &mut [u8]) -> IOCallbackResult<usize> {
        IOCallbackResult::WouldBlock
    }

    fn send(&mut self, _buf: &[u8]) -> IOCallbackResult<usize> {
        IOCallbackResult::WouldBlock
    }
}

// Every session takes a reference on the shared `WOLFSSL_CTX`. If those
// updates race, the context is freed while sessions still use it.
#[cfg(not(wolfssl_single_threaded))]
#[test]
fn shared_context_concurrent_sessions() {
    use std::sync::{Arc, Barrier};

    const THREADS: usize = 16;
    const SESSIONS_PER_THREAD: usize = 20_000;

    let ctx = Arc::new(ContextBuilder::new(Method::TlsClientV1_3).unwrap().build());
    let start = Arc::new(Barrier::new(THREADS));

    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let ctx = ctx.clone();
            let start = start.clone();
            thread::spawn(move || {
                start.wait();
                for _ in 0..SESSIONS_PER_THREAD {
                    drop(ctx.new_session(SessionConfig::new(NoIo)).unwrap());
                }
            })
        })
        .collect();

    for worker in workers {
        worker.join().unwrap();
    }
}

// Without internal locking wolfSSL must only be used by one thread at a
// time. Objects are `!Send` and `!Sync`, and creating objects or calling
// stateless functions from another thread panics. Run with
// `--test-threads=1` since tests in parallel would also trip this.
#[cfg(wolfssl_single_threaded)]
mod singlethreaded {
    use super::*;
    use wolfssl::{Aes256Gcm, Chacha20Poly1305Aead, Context, Random, Session};

    // Compiles only if `$t` does not implement `$trait`. Must be a macro: in
    // a generic fn the bound is never checked against the concrete type.
    macro_rules! assert_not_impl {
        ($t:ty: $trait:path) => {
            const _: fn() = || {
                trait AmbiguousIfImpl<A> {
                    fn some_item() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                struct Invalid;
                impl<T: ?Sized + $trait> AmbiguousIfImpl<Invalid> for T {}
                let _ = <$t as AmbiguousIfImpl<_>>::some_item;
            };
        };
    }

    assert_not_impl!(ContextBuilder: Send);
    assert_not_impl!(ContextBuilder: Sync);
    assert_not_impl!(Context: Send);
    assert_not_impl!(Context: Sync);
    assert_not_impl!(Session<NoIo>: Send);
    assert_not_impl!(Session<NoIo>: Sync);
    assert_not_impl!(Random: Send);
    assert_not_impl!(Random: Sync);
    assert_not_impl!(Aes256Gcm: Send);
    assert_not_impl!(Aes256Gcm: Sync);
    assert_not_impl!(Chacha20Poly1305Aead: Send);
    assert_not_impl!(Chacha20Poly1305Aead: Sync);

    fn panics_on_other_thread<F: FnOnce() + Send>(f: F) -> bool {
        thread::scope(|s| s.spawn(f).join().is_err())
    }

    fn context() -> Context {
        ContextBuilder::new(Method::TlsClientV1_3).unwrap().build()
    }

    #[test]
    fn context_created_from_other_thread_panics() {
        let ctx = context();
        assert!(panics_on_other_thread(|| {
            let _ = ContextBuilder::new(Method::TlsClientV1_3);
        }));
        // The owner keeps working after the rejected attempt.
        drop(ctx.new_session(SessionConfig::new(NoIo)).unwrap());
    }

    #[test]
    fn random_from_other_thread_panics() {
        let _ctx = context();
        assert!(panics_on_other_thread(|| drop(Random::new())));
    }

    #[test]
    fn aes_from_other_thread_panics() {
        let _ctx = context();
        assert!(panics_on_other_thread(|| drop(Aes256Gcm::new())));
        Aes256Gcm::new().unwrap();
    }

    #[test]
    fn chacha_from_other_thread_panics() {
        let _ctx = context();
        let key = [0; Chacha20Poly1305Aead::KEY_SIZE];
        assert!(panics_on_other_thread(|| {
            Chacha20Poly1305Aead::new(key);
        }));
        Chacha20Poly1305Aead::new(key);
    }

    #[test]
    fn error_string_from_other_thread_panics() {
        let _ctx = context();
        assert!(panics_on_other_thread(|| {
            let _ = wolfssl::ErrorKind::from(-1);
        }));
    }

    #[test]
    fn released_once_all_objects_dropped() {
        drop(context());
        assert!(!panics_on_other_thread(|| drop(context())));
        drop(context());
    }
}
