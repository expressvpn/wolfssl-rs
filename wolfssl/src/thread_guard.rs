//! wolfSSL built with `SINGLE_THREADED` has no internal locking or atomics.
//! Concurrent calls race even on unrelated objects, since reference counts,
//! DRBG state, CPU feature flags and the session cache are process-global.
//!
//! [`ThreadGuard`] lets one thread own wolfSSL for as long as it holds a
//! guard, and panics if another thread tries to take one meanwhile. Every
//! object holding a guard is `!Send` and `!Sync`, so it never leaves the
//! owning thread. In the default thread-safe build all of this compiles to
//! nothing.

use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};

// Objects rely on `ThreadPin` alone, so it must match the C build.
const _: () = assert!(wolfssl_sys::SINGLE_THREADED == cfg!(wolfssl_single_threaded));

/// Thread currently allowed to call into wolfSSL, `0` if none.
static OWNER: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static THREAD_ID: u64 = {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        NEXT.fetch_add(1, Ordering::Relaxed)
    };

    /// Number of live guards acquired by this thread.
    static HELD: Cell<usize> = const { Cell::new(0) };
}

/// Makes [`ThreadGuard`], and every object holding one, `!Send + !Sync`.
#[cfg(wolfssl_single_threaded)]
type ThreadPin = PhantomData<*mut ()>;
#[cfg(not(wolfssl_single_threaded))]
type ThreadPin = PhantomData<()>;

/// Held by every wolfSSL object. Ownership is released once the owning
/// thread drops its last guard.
#[derive(Debug)]
pub(crate) struct ThreadGuard(ThreadPin);

impl ThreadGuard {
    /// Claims wolfSSL for the current thread. Panics if another thread owns it.
    #[track_caller]
    pub(crate) fn acquire() -> Self {
        if wolfssl_sys::SINGLE_THREADED {
            let me = current_thread();
            if let Err(owner) = OWNER.compare_exchange(0, me, Ordering::Acquire, Ordering::Relaxed)
            {
                if owner != me {
                    wrong_thread();
                }
            }
            HELD.with(|held| held.set(held.get() + 1));
        }
        Self(PhantomData)
    }
}

impl Drop for ThreadGuard {
    fn drop(&mut self) {
        if wolfssl_sys::SINGLE_THREADED {
            HELD.with(|held| {
                let remaining = held.get() - 1;
                held.set(remaining);
                if remaining == 0 {
                    OWNER.store(0, Ordering::Release);
                }
            });
        }
    }
}

fn current_thread() -> u64 {
    THREAD_ID.with(|id| *id)
}

#[cold]
#[track_caller]
fn wrong_thread() -> ! {
    panic!("wolfSSL built with `singlethreaded` used from more than one thread")
}
