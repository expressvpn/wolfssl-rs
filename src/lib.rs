//! The `wolfssl` crate is designed to be a Rust layer built on top of
//! the `wolfssl-sys` crate (a C passthrough crate).

#![warn(missing_docs)]

mod async_client;
mod errors;

#[cfg(test)]
mod test_helpers;

pub use async_client::WolfClient;

use async_client::WolfClientCallbackContext;
use errors::{LoadRootCertificateError, WolfCleanupError, WolfError, WolfInitError};
use parking_lot::Mutex;
use tokio::io::ReadBuf;

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
    /// Turns this `WolfMethod` into a `WOLFSSL_METHOD*`. [[0]]
    ///
    /// WolfSSL only returns `NULL` if it cannot allocate the method
    /// struct. We handle it here by panicking.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html
    pub fn into_method_ptr(self) -> *mut wolfssl_sys::WOLFSSL_METHOD {
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
            ptr
        } else {
            panic!("WolfSSL is unable to allocate {self:?}");
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

#[allow(missing_docs)]
#[derive(Debug)]
pub struct WolfContextBuilder {
    ctx: *mut wolfssl_sys::WOLFSSL_CTX,
    method: WolfMethod,
}

impl WolfContextBuilder {
    /// Invokes [`wolfSSL_CTX_new`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_new
    pub fn new(method: WolfMethod) -> Option<Self> {
        let method_fn = method.into_method_ptr();

        let ctx = unsafe { wolfssl_sys::wolfSSL_CTX_new(method_fn) };

        if !ctx.is_null() {
            Some(Self { ctx, method })
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
                    self.ctx,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            RootCertificate::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_load_verify_buffer(
                    self.ctx,
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
                            self.ctx,
                            std::ptr::null(),
                            path.as_c_str().as_ptr(),
                        )
                    }
                } else {
                    unsafe {
                        wolfSSL_CTX_load_verify_locations(
                            self.ctx,
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

    /// Wraps [`wolfSSL_CTX_set_cipher_list`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_ctx_set_cipher_list
    pub fn with_cipher_list(self, cipher_list: &str) -> Option<Self> {
        let cipher_list = std::ffi::CString::new(cipher_list).ok()?;
        let result = unsafe {
            wolfssl_sys::wolfSSL_CTX_set_cipher_list(self.ctx, cipher_list.as_c_str().as_ptr())
        };
        if result == wolfssl_sys::WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }

    /// Wraps [`wolfSSL_CTX_use_certificate_file`][0] and [`wolfSSL_CTX_use_certificate_buffer`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_file
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_buffer
    pub fn with_certificate(self, secret: Secret) -> Option<Self> {
        use wolfssl_sys::{
            wolfSSL_CTX_use_certificate_buffer, wolfSSL_CTX_use_certificate_file,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM, WOLFSSL_SUCCESS,
        };

        let result = match secret {
            Secret::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_use_certificate_buffer(
                    self.ctx,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::Asn1File(path) => unsafe {
                let file = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_certificate_file(
                    self.ctx,
                    file.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_use_certificate_buffer(
                    self.ctx,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            Secret::PemFile(path) => unsafe {
                let file = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_certificate_file(
                    self.ctx,
                    file.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_PEM,
                )
            },
        };

        if result == WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }

    /// Wraps [`wolfSSL_CTX_use_PrivateKey_file`][0] and [`wolfSSL_CTX_use_PrivateKey_buffer`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_file
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_buffer
    pub fn with_private_key(self, secret: Secret) -> Option<Self> {
        use wolfssl_sys::{
            wolfSSL_CTX_use_PrivateKey_buffer, wolfSSL_CTX_use_PrivateKey_file,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM, WOLFSSL_SUCCESS,
        };

        let result = match secret {
            Secret::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_use_PrivateKey_buffer(
                    self.ctx,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::Asn1File(path) => unsafe {
                let path = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_PrivateKey_file(
                    self.ctx,
                    path.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_use_PrivateKey_buffer(
                    self.ctx,
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            Secret::PemFile(path) => unsafe {
                let path = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_PrivateKey_file(
                    self.ctx,
                    path.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_PEM,
                )
            },
        };

        if result == WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }

    /// Wraps `wolfSSL_CTX_UseSecureRenegotiation`
    ///
    // TODO (pangt): I can't seem to find documentation online for this.
    // this might also prompt a more general review of how we should
    // be checking for and handling errors (i.e; should we just
    // collect all error codes and throw it back up instead of
    // wrapping it in an enum?)
    pub fn with_secure_renegotiation(self) -> Option<Self> {
        let result = unsafe { wolfssl_sys::wolfSSL_CTX_UseSecureRenegotiation(self.ctx) };
        if result == wolfssl_sys::WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }

    /// Finalizes a `WolfContext`.
    pub fn build(self) -> WolfContext {
        WolfContext {
            method: self.method,
            ctx: self.ctx,
        }
    }
}

#[allow(missing_docs)]
pub struct WolfContext {
    method: WolfMethod,
    ctx: *mut wolfssl_sys::WOLFSSL_CTX,
}

/// This is necessary because `WolfContext` will need to cross
/// `.await` boundaries, which means it must be safe to transfer
/// across threads.
///
/// We cannot specify just `wolfssl_sys::WOLFSSL_CTX` because of
/// orphan rules.
///
// TODO (pangt): Perhaps store the pointer inside something `Send`
// instead
unsafe impl Send for WolfContext {}

impl WolfContext {
    /// Returns the [`WolfMethod`] used to initialize this
    /// [`WolfContext`].
    pub fn method(&self) -> WolfMethod {
        self.method
    }

    /// Invokes [`wolfSSL_new`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_new
    pub fn new_session(&self) -> Option<WolfSession> {
        let ptr = unsafe { wolfssl_sys::wolfSSL_new(self.ctx) };
        if !ptr.is_null() {
            Some(WolfSession(Mutex::new(ptr)))
        } else {
            None
        }
    }
}

impl Drop for WolfContext {
    /// Invokes [`wolfSSL_CTX_free`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_free
    fn drop(&mut self) {
        unsafe { wolfssl_sys::wolfSSL_CTX_free(self.ctx) }
    }
}

#[allow(missing_docs)]
pub struct WolfSession(Mutex<*mut wolfssl_sys::WOLFSSL>);

impl WolfSession {
    /// Gets the current cipher of the session. If there is no cipher,
    /// returns `Some("NONE")`.
    pub fn get_current_cipher_name(&self) -> Option<String> {
        let ssl = self.0.lock();
        let cipher = unsafe { wolfssl_sys::wolfSSL_get_current_cipher(*ssl) };
        if !cipher.is_null() {
            let name = unsafe {
                let name = wolfssl_sys::wolfSSL_CIPHER_get_name(cipher);
                std::ffi::CStr::from_ptr(name).to_str().ok()?.to_string()
            };
            Some(name)
        } else {
            None
        }
    }

    /// Invokes [`wolfSSL_is_init_finished`][0]
    ///
    /// "Init" in this case is the formation of the TLS connection.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_is_init_finished
    pub fn is_init_finished(&self) -> bool {
        let ssl = self.0.lock();
        match unsafe { wolfssl_sys::wolfSSL_is_init_finished(*ssl) } {
            0 => false,
            1 => true,
            _ => unimplemented!("Only 0 or 1 is expected as return value"),
        }
    }

    /// Wraps [`wolfSSL_accept`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_accept
    pub(crate) fn try_accept(&self) -> Result<(), WolfError> {
        let ssl = self.0.lock();
        if unsafe { wolfssl_sys::wolfSSL_accept(*ssl) } == wolfssl_sys::WOLFSSL_FATAL_ERROR {
            Err(WolfError::get_error(*ssl, wolfssl_sys::WOLFSSL_FATAL_ERROR))
        } else {
            Ok(())
        }
    }

    /// Wraps [`wolfSSL_connect`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_connect
    pub(crate) fn try_connect(&self) -> Result<(), WolfError> {
        let ssl = self.0.lock();
        if unsafe { wolfssl_sys::wolfSSL_connect(*ssl) } == wolfssl_sys::WOLFSSL_FATAL_ERROR {
            Err(WolfError::get_error(*ssl, wolfssl_sys::WOLFSSL_FATAL_ERROR))
        } else {
            Ok(())
        }
    }

    /// Wraps [`wolfSSL_negotiate`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_negotiate
    pub(crate) fn try_negotiate(&self) -> Result<(), WolfError> {
        let ssl = self.0.lock();
        if unsafe { wolfssl_sys::wolfSSL_negotiate(*ssl) } == wolfssl_sys::WOLFSSL_FATAL_ERROR {
            Err(WolfError::get_error(*ssl, wolfssl_sys::WOLFSSL_FATAL_ERROR))
        } else {
            Ok(())
        }
    }

    /// Registers a [`WolfClientCallbackContext`] to this `WOLFSSL`
    /// session.
    ///
    /// This is done via [`wolfSSL_SetIOReadCtx`][0] and
    /// [`wolfSSL_SetIOWriteCtx`][1].
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setioreadctx
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setiowritectx
    ///
    // TODO (pangt): It's not clear how safe this is. Should it at
    // least be `Pin`?
    pub(crate) fn set_io_context(&self, ctx: &mut WolfClientCallbackContext) {
        let ssl_session_ptr = self.0.lock();
        let session_context_ptr = ctx as *mut _ as *mut ::std::os::raw::c_void;
        unsafe {
            wolfssl_sys::wolfSSL_SetIOReadCtx(*ssl_session_ptr, session_context_ptr);
            wolfssl_sys::wolfSSL_SetIOWriteCtx(*ssl_session_ptr, session_context_ptr);
        }
    }

    /// Invokes [`wolfSSL_read`][0] and fills `buf` with the results
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_read
    pub(crate) fn read_into(&self, buf: &mut ReadBuf) -> Result<usize, WolfError> {
        let ssl = self.0.lock();
        match unsafe {
            wolfssl_sys::wolfSSL_read(
                *ssl,
                &mut buf.initialize_unfilled()[..] as *mut _ as *mut ::std::os::raw::c_void,
                buf.remaining() as i32,
            )
        } {
            x if x > 0 => {
                buf.advance(x as usize);
                Ok(x as usize)
            }
            x if x <= 0 => Err(WolfError::get_error(*ssl, x)),
            x => {
                unreachable!("Unhandled wolfSSL_read return value {x}");
            }
        }
    }

    /// Invokes [`wolfSSL_write`][0] and write the value of `buf`.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_write
    pub(crate) fn write(&self, buf: &[u8]) -> Result<usize, WolfError> {
        let ssl = self.0.lock();
        match unsafe {
            let buf_ptr = buf as *const _ as *const ::std::os::raw::c_void;
            wolfssl_sys::wolfSSL_write(*ssl, buf_ptr, buf.len() as i32)
        } {
            x if x <= 0 => Err(WolfError::get_error(*ssl, x)),
            x if x > 0 => Ok(x as usize),
            x => {
                unreachable!("Unhandled wolfSSL_write return value {x}");
            }
        }
    }
}

impl Drop for WolfSession {
    /// Invokes [`wolfSSL_free`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_free
    fn drop(&mut self) {
        let ssl = self.0.lock();
        unsafe { wolfssl_sys::wolfSSL_free(*ssl) }
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
        let _ = method.into_method_ptr();
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

    #[test]
    fn wolf_context_set_cipher_list() {
        let _ = WolfContextBuilder::new(WolfMethod::DtlsClient)
            .unwrap()
            // This string might need to change depending on the flags
            // we built wolfssl with.
            .with_cipher_list("TLS13-CHACHA20-POLY1305-SHA256")
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn wolf_context_set_certificate_buffer() {
        const SERVER_CERT: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/server_cert_der_2048"
        ));

        let cert = Secret::Asn1Buffer(SERVER_CERT);

        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_certificate(cert)
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn wolf_context_set_private_key_buffer() {
        const SERVER_KEY: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/server_key_der_2048"
        ));

        let key = Secret::Asn1Buffer(SERVER_KEY);

        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_private_key(key)
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn wolf_context_set_secure_renegotiation() {
        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_secure_renegotiation()
            .unwrap();

        wolf_cleanup().unwrap();
    }
}
