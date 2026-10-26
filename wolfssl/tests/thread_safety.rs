//! Sharing wolfSSL objects across threads must never be undefined behaviour.

#![deny(unsafe_code)] // unsafety should all be in the library.

use std::sync::{Arc, Barrier};
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
#[cfg(not(feature = "singlethreaded"))]
#[test]
fn shared_context_concurrent_sessions() {
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
