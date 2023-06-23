//! The `wolfssl` crate is designed to be a Rust layer built on top of
//! the `wolfssl-sys` crate (a C passthrough crate).

#![warn(missing_docs)]

mod context;
mod errors;
mod session;

use errors::{WolfCleanupError, WolfInitError};

pub use context::*;
pub use session::*;

/// Wraps [`wolfSSL_Init`][0]
///
/// Note that this is also internally during initialization by
/// [`WolfContextBuilder`].
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_init
pub fn wolf_init() -> Result<(), WolfInitError> {
    match unsafe { wolfssl_sys::wolfSSL_Init() } {
        wolfssl_sys::WOLFSSL_SUCCESS => Ok(()),
        wolfssl_sys::BAD_MUTEX_E => Err(WolfInitError::Mutex),
        wolfssl_sys::WC_INIT_E => Err(WolfInitError::WolfCrypt),
        e => panic!("Unexpected return value from `wolfSSL_Init`. Got {e}"),
    }
}

/// Wraps [`wolfSSL_Cleanup`][0]
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_cleanup
pub fn wolf_cleanup() -> Result<(), WolfCleanupError> {
    match unsafe { wolfssl_sys::wolfSSL_Cleanup() } {
        wolfssl_sys::WOLFSSL_SUCCESS => Ok(()),
        wolfssl_sys::BAD_MUTEX_E => Err(WolfCleanupError::Mutex),
        e => panic!("Unexpected return value from `wolfSSL_Cleanup. Got {e}`"),
    }
}

/// Corresponds to the various `wolf*_{client,server}_method()` APIs
#[derive(Debug, Copy, Clone)]
pub enum WolfMethod {
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

impl WolfMethod {
    /// Converts a [`WolfMethod`] into a [`wolfssl_sys::WOLFSSL_METHOD`]
    /// compatible with [`wolfssl_sys::wolfSSL_CTX_new`]
    pub fn into_method_ptr(self) -> Option<*mut wolfssl_sys::WOLFSSL_METHOD> {
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

        if !ptr.is_null() {
            Some(ptr)
        } else {
            None
        }
    }
}

#[allow(missing_docs)]
pub enum RootCertificate<'a> {
    PemBuffer(&'a [u8]),
    Asn1Buffer(&'a [u8]),
    PemFileOrDirectory(&'a std::path::Path),
}

#[allow(missing_docs)]
pub enum Secret<'a> {
    Asn1Buffer(&'a [u8]),
    Asn1File(&'a std::path::Path),
    PemBuffer(&'a [u8]),
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
