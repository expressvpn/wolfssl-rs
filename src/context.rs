use crate::{
    callback::{wolf_tls_read_cb, wolf_tls_write_cb},
    error::{Error, Result},
    ssl::{Session, SessionConfig},
    Protocol, RootCertificate, Secret,
};
use parking_lot::{Mutex, MutexGuard};
use std::ptr::NonNull;

/// Produces a [`Context`] once built.
#[derive(Debug)]
pub struct ContextBuilder {
    ctx: NonNull<wolfssl_sys::WOLFSSL_CTX>,
    protocol: Protocol,
}

impl ContextBuilder {
    /// Invokes [`wolfSSL_CTX_new`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_new
    pub fn new(protocol: Protocol) -> Option<Self> {
        let method_fn = protocol.into_method_ptr()?;

        let ctx = unsafe { wolfssl_sys::wolfSSL_CTX_new(method_fn.as_ptr()) };
        let ctx = NonNull::new(ctx)?;

        Some(Self { ctx, protocol })
    }

    /// Wraps [`wolfSSL_CTX_load_verify_buffer`][0] and [`wolfSSL_CTX_load_verify_locations`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_buffer
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_locations
    pub fn with_root_certificate(self, root: RootCertificate) -> Result<Self> {
        use wolfssl_sys::{
            wolfSSL_CTX_load_verify_buffer, wolfSSL_CTX_load_verify_locations,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM,
        };

        let result = match root {
            RootCertificate::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_load_verify_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            RootCertificate::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_load_verify_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            RootCertificate::PemFileOrDirectory(path) => {
                let is_dir = path.is_dir();
                let path = path
                    .to_str()
                    .ok_or(Error::fatal(wolfssl_sys::WOLFSSL_BAD_PATH))?;
                let path = std::ffi::CString::new(path)
                    .or(Err(Error::fatal(wolfssl_sys::WOLFSSL_BAD_PATH)))?;
                if is_dir {
                    unsafe {
                        wolfSSL_CTX_load_verify_locations(
                            self.ctx.as_ptr(),
                            std::ptr::null(),
                            path.as_c_str().as_ptr(),
                        )
                    }
                } else {
                    unsafe {
                        wolfSSL_CTX_load_verify_locations(
                            self.ctx.as_ptr(),
                            path.as_c_str().as_ptr(),
                            std::ptr::null(),
                        )
                    }
                }
            }
        };

        if result == wolfssl_sys::WOLFSSL_SUCCESS {
            Ok(self)
        } else {
            Err(Error::fatal(result))
        }
    }

    /// Wraps [`wolfSSL_CTX_set_cipher_list`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_ctx_set_cipher_list
    pub fn with_cipher_list(self, cipher_list: &str) -> Result<Self> {
        let cipher_list = std::ffi::CString::new(cipher_list)
            .or(Err(Error::fatal(wolfssl_sys::WOLFSSL_FAILURE)))?;

        let result = unsafe {
            wolfssl_sys::wolfSSL_CTX_set_cipher_list(
                self.ctx.as_ptr(),
                cipher_list.as_c_str().as_ptr(),
            )
        };

        if result == wolfssl_sys::WOLFSSL_SUCCESS {
            Ok(self)
        } else {
            Err(Error::fatal(result))
        }
    }

    /// Wraps [`wolfSSL_CTX_use_certificate_file`][0] and [`wolfSSL_CTX_use_certificate_buffer`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_file
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_buffer
    pub fn with_certificate(self, secret: Secret) -> Result<Self> {
        use wolfssl_sys::{
            wolfSSL_CTX_use_certificate_buffer, wolfSSL_CTX_use_certificate_file,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM,
        };

        let result = match secret {
            Secret::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_use_certificate_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::Asn1File(path) => unsafe {
                let path = path
                    .to_str()
                    .ok_or(Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                let file = std::ffi::CString::new(path)
                    .or(Err(Error::fatal(wolfssl_sys::BAD_PATH_ERROR)))?;
                wolfSSL_CTX_use_certificate_file(
                    self.ctx.as_ptr(),
                    file.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_use_certificate_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            Secret::PemFile(path) => unsafe {
                let path = path
                    .to_str()
                    .ok_or(Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                let file = std::ffi::CString::new(path)
                    .or(Err(Error::fatal(wolfssl_sys::BAD_PATH_ERROR)))?;
                wolfSSL_CTX_use_certificate_file(
                    self.ctx.as_ptr(),
                    file.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_PEM,
                )
            },
        };

        if result == wolfssl_sys::WOLFSSL_SUCCESS {
            Ok(self)
        } else {
            Err(Error::fatal(result))
        }
    }

    /// Wraps [`wolfSSL_CTX_use_PrivateKey_file`][0] and [`wolfSSL_CTX_use_PrivateKey_buffer`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_file
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_buffer
    pub fn with_private_key(self, secret: Secret) -> Result<Self> {
        use wolfssl_sys::{
            wolfSSL_CTX_use_PrivateKey_buffer, wolfSSL_CTX_use_PrivateKey_file,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM,
        };

        let result = match secret {
            Secret::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_use_PrivateKey_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::Asn1File(path) => unsafe {
                let path = path
                    .to_str()
                    .ok_or(Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                let file = std::ffi::CString::new(path)
                    .or(Err(Error::fatal(wolfssl_sys::BAD_PATH_ERROR)))?;
                wolfSSL_CTX_use_PrivateKey_file(
                    self.ctx.as_ptr(),
                    file.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_use_PrivateKey_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            Secret::PemFile(path) => unsafe {
                let path = path
                    .to_str()
                    .ok_or(Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                let file = std::ffi::CString::new(path)
                    .or(Err(Error::fatal(wolfssl_sys::BAD_PATH_ERROR)))?;
                wolfSSL_CTX_use_PrivateKey_file(
                    self.ctx.as_ptr(),
                    file.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_PEM,
                )
            },
        };

        if result == wolfssl_sys::WOLFSSL_SUCCESS {
            Ok(self)
        } else {
            Err(Error::fatal(result))
        }
    }

    /// Wraps `wolfSSL_CTX_UseSecureRenegotiation`
    ///
    // NOTE (pangt): I can't seem to find documentation online for this.
    pub fn with_secure_renegotiation(self) -> Result<Self> {
        let result = unsafe { wolfssl_sys::wolfSSL_CTX_UseSecureRenegotiation(self.ctx.as_ptr()) };
        if result == wolfssl_sys::WOLFSSL_SUCCESS {
            Ok(self)
        } else {
            Err(Error::fatal(result))
        }
    }

    /// Finalizes a `WolfContext`.
    pub fn build(mut self) -> Context {
        self.register_io_callbacks();
        Context {
            protocol: self.protocol,
            ctx: Mutex::new(self.ctx),
        }
    }
}

impl ContextBuilder {
    fn register_io_callbacks(&mut self) {
        let ctx = self.ctx;
        unsafe {
            wolfssl_sys::wolfSSL_CTX_SetIORecv(ctx.as_ptr(), Some(wolf_tls_read_cb));
            wolfssl_sys::wolfSSL_CTX_SetIOSend(ctx.as_ptr(), Some(wolf_tls_write_cb));
        }
    }
}

/// A wrapper around a `WOLFSSL_CTX`.
pub struct Context {
    protocol: Protocol,
    ctx: Mutex<NonNull<wolfssl_sys::WOLFSSL_CTX>>,
}

impl Context {
    /// Gets the underlying [`wolfssl_sys::WOLFSSL_CTX`] pointer that this is
    /// managing.
    pub fn ctx(&self) -> MutexGuard<NonNull<wolfssl_sys::WOLFSSL_CTX>> {
        self.ctx.lock()
    }

    /// Returns the Context's [`Protocol`].
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Creates a new SSL session using this underlying context.
    pub fn new_session(&self, config: SessionConfig) -> Option<Session> {
        Session::new_from_context(self, config)
    }
}

impl Drop for Context {
    /// Invokes [`wolfSSL_CTX_free`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_free
    fn drop(&mut self) {
        unsafe { wolfssl_sys::wolfSSL_CTX_free(self.ctx.lock().as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{wolf_cleanup, wolf_init};
    use test_case::test_case;

    #[test_case(Protocol::DtlsClient)]
    #[test_case(Protocol::DtlsClientV1_2)]
    #[test_case(Protocol::DtlsServer)]
    #[test_case(Protocol::DtlsServerV1_2)]
    #[test_case(Protocol::TlsClient)]
    #[test_case(Protocol::TlsClientV1_2)]
    #[test_case(Protocol::TlsClientV1_3)]
    #[test_case(Protocol::TlsServer)]
    #[test_case(Protocol::TlsServerV1_2)]
    #[test_case(Protocol::TlsServerV1_3)]
    fn wolfssl_context_new(protocol: Protocol) {
        wolf_init().unwrap();
        let _ = protocol.into_method_ptr().unwrap();
        wolf_cleanup().unwrap();
    }

    #[test]
    fn new() {
        ContextBuilder::new(Protocol::DtlsClient).unwrap();
        wolf_cleanup().unwrap();
    }

    #[test]
    fn root_certificate_buffer() {
        const CA_CERT: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/ca_cert_der_2048"
        ));

        let cert = RootCertificate::Asn1Buffer(CA_CERT);

        let _ = ContextBuilder::new(Protocol::TlsClient)
            .unwrap()
            .with_root_certificate(cert)
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn set_cipher_list() {
        let _ = ContextBuilder::new(Protocol::DtlsClient)
            .unwrap()
            // This string might need to change depending on the flags
            // we built wolfssl with.
            .with_cipher_list("TLS13-CHACHA20-POLY1305-SHA256")
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn set_certificate_buffer() {
        const SERVER_CERT: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/server_cert_der_2048"
        ));

        let cert = Secret::Asn1Buffer(SERVER_CERT);

        let _ = ContextBuilder::new(Protocol::TlsClient)
            .unwrap()
            .with_certificate(cert)
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn set_private_key_buffer() {
        const SERVER_KEY: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/server_key_der_2048"
        ));

        let key = Secret::Asn1Buffer(SERVER_KEY);

        let _ = ContextBuilder::new(Protocol::TlsClient)
            .unwrap()
            .with_private_key(key)
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn set_secure_renegotiation() {
        let _ = ContextBuilder::new(Protocol::TlsClient)
            .unwrap()
            .with_secure_renegotiation()
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn register_io_callbacks() {
        let _ = ContextBuilder::new(Protocol::TlsClient).unwrap().build();
    }
}
