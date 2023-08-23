//! The `wolfssl` crate is designed to be a Rust layer built on top of
//! the `wolfssl-sys` crate (a C passthrough crate).

#![warn(missing_docs)]

mod callback;
mod context;
mod error;
mod rng;
mod ssl;

pub use context::*;
pub use rng::*;
pub use ssl::*;

use error::{Error, Result};

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
/// Note that this is also internally during initialization by
/// [`ContextBuilder`].
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_init
pub fn wolf_init() -> Result<()> {
    match unsafe { wolfssl_sys::wolfSSL_Init() } {
        wolfssl_sys::WOLFSSL_SUCCESS => Ok(()),
        e => Err(Error::fatal(e)),
    }
}

/// Wraps [`wolfSSL_Cleanup`][0]
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_cleanup
pub fn wolf_cleanup() -> Result<()> {
    match unsafe { wolfssl_sys::wolfSSL_Cleanup() } {
        wolfssl_sys::WOLFSSL_SUCCESS => Ok(()),
        e => Err(Error::fatal(e)),
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
    pub fn into_method_ptr(self) -> Option<NonNull<wolfssl_sys::WOLFSSL_METHOD>> {
        let ptr = match self {
            Self::DtlsClient => unsafe { wolfssl_sys::wolfDTLS_client_method() },
            Self::DtlsClientV1_2 => unsafe { wolfssl_sys::wolfDTLSv1_2_client_method() },
            Self::DtlsServer => unsafe { wolfssl_sys::wolfDTLS_server_method() },
            Self::DtlsServerV1_2 => unsafe { wolfssl_sys::wolfDTLSv1_2_server_method() },
            Self::TlsClient => unsafe { wolfssl_sys::wolfTLS_client_method() },
            Self::TlsClientV1_2 => unsafe { wolfssl_sys::wolfTLSv1_2_client_method() },
            Self::TlsClientV1_3 => unsafe { wolfssl_sys::wolfTLSv1_3_client_method() },
            Self::TlsServer => unsafe { wolfssl_sys::wolfTLS_server_method() },
            Self::TlsServerV1_2 => unsafe { wolfssl_sys::wolfTLSv1_2_server_method() },
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

    #[test]
    fn wolf_cleanup_test() {
        wolf_cleanup().unwrap();
    }
}
