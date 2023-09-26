//! The `wolfssl` crate is designed to be a Rust layer built on top of
//! the `wolfssl-sys` crate (a C passthrough crate).

#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(missing_docs)]

mod callback;
mod context;
mod error;
mod rng;
mod ssl;

pub use callback::*;
pub use context::*;
pub use rng::*;
pub use ssl::*;

pub use error::{Error, Poll, Result};

use std::ptr::NonNull;

/// Record size is defined as `2^14 + 1`.
///
/// > ...the full encoded TLSInnerPlaintext MUST NOT exceed 2^14 + 1
/// > octets
/// - [source][0]
///
/// This value must also equal or exceed `<wolfssl/internal.h>`'s
/// `MAX_RECORD_SIZE` (though I'm not sure how to assert that yet).
///
/// [0]: https://www.rfc-editor.org/rfc/rfc8446#section-5.4
const TLS_MAX_RECORD_SIZE: usize = 2usize.pow(14) + 1;

/// Wraps [`wolfSSL_Init`][0]
///
/// This must be called internally by any binding which uses a library function.
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_init
fn wolf_init() -> Result<()> {
    static ONCE: std::sync::OnceLock<Result<()>> = std::sync::OnceLock::new();

    ONCE.get_or_init(|| {
        // SAFETY: [`wolfSSL_Init`][0] ([also][1]) must be called once
        // per application, this is enforced using the `ONCE:
        // OnceLock` and by ensuring that all entry points into this
        // crate call this method.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_init
        // [1]: https://www.wolfssl.com/doxygen/group__TLS.html#ga789ef74e34df659a62f06da2ea709737
        match unsafe { wolfssl_sys::wolfSSL_Init() } {
            wolfssl_sys::WOLFSSL_SUCCESS => Ok(()),
            e => Err(Error::fatal(e)),
        }
    })
    .clone()
}

/// Wraps [`wolfSSL_Debugging_ON`][0] and [`wolfSSL_Debugging_OFF`][1]
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_on
/// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_off
#[cfg(feature = "debug")]
pub fn enable_debugging(on: bool) {
    wolf_init().expect("Unable to initialize wolfSSL");

    if on {
        // SAFETY: [`wolfSSL_Debugging_ON`][0] ([also][1]) requires `DEBUG_WOLFSSL` to be compiled in to succeed
        // This function will be compiled only on enabling feature `debug`
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_on
        // [1]: https://www.wolfssl.com/doxygen/group__Debug.html#ga192a2501d23697c2b56ce26b1af0eb2c
        match unsafe { wolfssl_sys::wolfSSL_Debugging_ON() } {
            0 => {}
            // This wrapper function is only enabled if we built wolfssl-sys with debugging on.
            wolfssl_sys::NOT_COMPILED_IN => {
                panic!("Inconsistent build, debug not enabled in wolfssl_sys")
            }
            e => unreachable!("{e:?}"),
        }
    } else {
        // SAFETY: [`wolfSSL_Debugging_OFF`][0] ([also][1]) has no safety concerns as per documentation
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_off
        // [1]: https://www.wolfssl.com/doxygen/group__Debug.html#gafa8dab742182b891d80300fb195399ce
        unsafe { wolfssl_sys::wolfSSL_Debugging_OFF() }
    }
}

/// Corresponds to the various `wolf*_{client,server}_method()` APIs
#[derive(Debug, Copy, Clone)]
pub enum Protocol {
    /// `wolfDTLS_client_method`
    DtlsClient,
    /// `wolfDTLSv1_2_client_method`
    DtlsClientV1_2,
    /// `wolfDTLS_server_method`
    DtlsServer,
    /// `wolfDTLSv1_2_server_method`
    DtlsServerV1_2,
    /// `wolfTLS_client_method`
    TlsClient,
    /// `wolfTLSv1_2_client_method`
    TlsClientV1_2,
    /// `wolfTLSv1_3_client_method`
    TlsClientV1_3,
    /// `wolfTLS_server_method`
    TlsServer,
    /// `wolfTLSv1_2_server_method`
    TlsServerV1_2,
    /// `wolfTLSv1_3_server_method`
    TlsServerV1_3,
}

impl Protocol {
    /// Converts a [`Self`] into a [`wolfssl_sys::WOLFSSL_METHOD`]
    /// compatible with [`wolfssl_sys::wolfSSL_CTX_new`]
    fn into_method_ptr(self) -> Option<NonNull<wolfssl_sys::WOLFSSL_METHOD>> {
        let ptr = match self {
            // SAFETY: Per documentation [`wolfDTLS_client_method][0] and its sibling methods allocate memory for `WOLFSSL_METHOD` and initialize with proper values.
            // The documentation is unclear about when to free the memory.
            // Based on implementation[2], the api [`wolfSSL_CTX_new`][1] will consume this memory and thus take care of freeing it
            //
            // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfsslv3_client_method
            // [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_new
            // [2]: https://github.com/wolfSSL/wolfssl/blob/v5.6.3-stable/src/internal.c#L2156
            Self::DtlsClient => unsafe { wolfssl_sys::wolfDTLS_client_method() },
            // SAFETY: as above
            Self::DtlsClientV1_2 => unsafe { wolfssl_sys::wolfDTLSv1_2_client_method() },
            // SAFETY: as above
            Self::DtlsServer => unsafe { wolfssl_sys::wolfDTLS_server_method() },
            // SAFETY: as above
            Self::DtlsServerV1_2 => unsafe { wolfssl_sys::wolfDTLSv1_2_server_method() },
            // SAFETY: as above
            Self::TlsClient => unsafe { wolfssl_sys::wolfTLS_client_method() },
            // SAFETY: as above
            Self::TlsClientV1_2 => unsafe { wolfssl_sys::wolfTLSv1_2_client_method() },
            // SAFETY: as above
            Self::TlsClientV1_3 => unsafe { wolfssl_sys::wolfTLSv1_3_client_method() },
            // SAFETY: as above
            Self::TlsServer => unsafe { wolfssl_sys::wolfTLS_server_method() },
            // SAFETY: as above
            Self::TlsServerV1_2 => unsafe { wolfssl_sys::wolfTLSv1_2_server_method() },
            // SAFETY: as above
            Self::TlsServerV1_3 => unsafe { wolfssl_sys::wolfTLSv1_3_server_method() },
        };

        NonNull::new(ptr)
    }

    /// Checks if the method is compatible with TLS 1.3
    fn is_tls_13(&self) -> bool {
        matches!(self, Self::TlsClientV1_3 | Self::TlsServerV1_3)
    }
}

/// Defines a CA certificate
pub enum RootCertificate<'a> {
    /// In-memory PEM buffer
    PemBuffer(&'a [u8]),
    /// In-memory ASN1 buffer
    Asn1Buffer(&'a [u8]),
    /// Path to a PEM file, or a directory of PEM files
    PemFileOrDirectory(&'a std::path::Path),
}

/// Defines either a public or private key
pub enum Secret<'a> {
    /// In-memory ASN1 buffer
    Asn1Buffer(&'a [u8]),
    /// Path to ASN1 file
    Asn1File(&'a std::path::Path),
    /// In-memory PEM buffer
    PemBuffer(&'a [u8]),
    /// Path to PEM file
    PemFile(&'a std::path::Path),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wolf_init_test() {
        wolf_init().unwrap();
    }
}
