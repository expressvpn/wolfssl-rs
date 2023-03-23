//! The `wolfssl` crate is designed to be a Rust layer built on top of
//! the `wolfssl-sys` crate (a C passthrough crate).

#![warn(missing_docs)]

mod errors;

use errors::{LoadRootCertificateError, WolfCleanupError, WolfInitError};

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
pub struct WolfContextBuilder(*mut wolfssl_sys::WOLFSSL_CTX);

impl WolfContextBuilder {
    /// Invokes [`wolfSSL_CTX_new`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_new
    pub fn new(method: WolfMethod) -> Option<Self> {
        let method_fn = method.into_method_ptr()?;

        let ctx = unsafe { wolfssl_sys::wolfSSL_CTX_new(method_fn) };

        if !ctx.is_null() {
            Some(Self(ctx))
        } else {
            None
        }
    }

    /// Wraps [`wolfSSL_CTX_load_verify_buffer`][0] and [`wolfSSL_CTX_load_verify_locations`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_buffer
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_locations
    pub fn with_root_certificate(
        self,
        root: RootCertificate,
    ) -> Result<Self, LoadRootCertificateError> {
        use wolfssl_sys::{
            wolfSSL_CTX_load_verify_buffer, wolfSSL_CTX_load_verify_locations,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM, WOLFSSL_SUCCESS,
        };

        let result = match root {
            RootCertificate::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_load_verify_buffer(
                    self.0,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            RootCertificate::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_load_verify_buffer(
                    self.0,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            RootCertificate::PemFileOrDirectory(path) => {
                let is_dir = path.is_dir();
                let path =
                    std::ffi::CString::new(path.to_str().ok_or(LoadRootCertificateError::Path)?)
                        .map_err(|_| LoadRootCertificateError::Path)?;
                if is_dir {
                    unsafe {
                        wolfSSL_CTX_load_verify_locations(
                            self.0,
                            std::ptr::null(),
                            path.as_c_str().as_ptr(),
                        )
                    }
                } else {
                    unsafe {
                        wolfSSL_CTX_load_verify_locations(
                            self.0,
                            path.as_c_str().as_ptr(),
                            std::ptr::null(),
                        )
                    }
                }
            }
        };

        if result == WOLFSSL_SUCCESS {
            Ok(self)
        } else {
            Err(LoadRootCertificateError::from(result))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test]
    fn wolf_init_test() {
        wolf_init().unwrap();
    }

    #[test]
    fn wolf_cleanup_test() {
        wolf_cleanup().unwrap();
    }

    #[test_case(WolfMethod::DtlsClient)]
    #[test_case(WolfMethod::DtlsClientV1_2)]
    #[test_case(WolfMethod::DtlsServer)]
    #[test_case(WolfMethod::DtlsServerV1_2)]
    #[test_case(WolfMethod::TlsClient)]
    #[test_case(WolfMethod::TlsClientV1_2)]
    #[test_case(WolfMethod::TlsClientV1_3)]
    #[test_case(WolfMethod::TlsServer)]
    #[test_case(WolfMethod::TlsServerV1_2)]
    #[test_case(WolfMethod::TlsServerV1_3)]
    fn wolfssl_context_new(method: WolfMethod) {
        wolf_init().unwrap();
        let _ = method.into_method_ptr().unwrap();
        wolf_cleanup().unwrap();
    }

    #[test]
    fn wolf_context_new() {
        WolfContextBuilder::new(WolfMethod::DtlsClient).unwrap();
        wolf_cleanup().unwrap();
    }

    #[test]
    fn wolf_context_root_certificate_buffer() {
        const CA_CERT: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/ca_cert_der_2048"
        ));

        let cert = RootCertificate::Asn1Buffer(CA_CERT);

        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_root_certificate(cert)
            .unwrap();

        wolf_cleanup().unwrap();
    }
}
