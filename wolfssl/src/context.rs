use crate::{
    callback::IOCallbacks,
    error::{Error, Result},
    ssl::{Session, SessionConfig},
    CurveGroup, NewSessionError, Protocol, RootCertificate, Secret, SslVerifyMode,
};
use std::ptr::NonNull;
use thiserror::Error;

/// Produces a [`Context`] once built.
#[derive(Debug)]
pub struct ContextBuilder {
    ctx: NonNull<wolfssl_sys::WOLFSSL_CTX>,
    protocol: Protocol,
}

/// Error creating a [`ContextBuilder`] object.
#[derive(Error, Debug)]
pub enum NewContextBuilderError {
    /// Failed to initialize WolfSSL
    #[error("Failed to initialize WolfSSL: {0}")]
    InitFailed(Error),

    /// Failed to turn `Protocol` into a `wolfssl_sys::WOLFSSL_METHOD`
    #[error("Failed to obtain WOLFSSL_METHOD")]
    MethodFailed,

    /// `wolfSSL_CTX_new` failed
    #[error("Failed to allocate WolfSSL Context")]
    CreateFailed,
}

impl ContextBuilder {
    /// Invokes [`wolfSSL_CTX_new`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_new
    pub fn new(protocol: Protocol) -> std::result::Result<Self, NewContextBuilderError> {
        crate::wolf_init().map_err(NewContextBuilderError::InitFailed)?;

        let method_fn = protocol
            .into_method_ptr()
            .ok_or(NewContextBuilderError::MethodFailed)?;

        // SAFETY: [`wolfSSL_CTX_new`][0] is documented to get pointer to a valid `WOLFSSL_METHOD` structure which is created using one of the `wolfSSLvXX_XXXX_method()`.
        // `Protocol::into_method_ptr` function returns a pointer `wolfSSLvXX_XXXX_method()`
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_new
        let ctx = unsafe { wolfssl_sys::wolfSSL_CTX_new(method_fn.as_ptr()) };
        let ctx = NonNull::new(ctx).ok_or(NewContextBuilderError::CreateFailed)?;

        Ok(Self { ctx, protocol })
    }

    /// When `cond` is True call fallible `func` on `Self`
    pub fn try_when<F>(self, cond: bool, func: F) -> Result<Self>
    where
        F: FnOnce(Self) -> Result<Self>,
    {
        if cond {
            func(self)
        } else {
            Ok(self)
        }
    }

    /// When `maybe` is Some(_) call fallible `func` on `Self` and the contained value
    pub fn try_when_some<F, T>(self, maybe: Option<T>, func: F) -> Result<Self>
    where
        F: FnOnce(Self, T) -> Result<Self>,
    {
        if let Some(t) = maybe {
            func(self, t)
        } else {
            Ok(self)
        }
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
            // SAFETY: [`wolfSSL_CTX_load_verify_buffer`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
            // The pointer given as the `in` argument must point to a region of `sz` bytes.
            // The values passed here are valid since they are derived from the same byte slice.
            //
            // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_buffer
            // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#gaa5a28f0ac25d9abeb72fcee81bbf647b
            RootCertificate::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_load_verify_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            // SAFETY: [`wolfSSL_CTX_load_verify_buffer`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
            // The pointer given as the `in` argument must point to a region of `sz` bytes.
            // The values passed here are valid since they are derived from the same byte slice.
            //
            // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_buffer
            // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#gaa5a28f0ac25d9abeb72fcee81bbf647b
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
                    .ok_or_else(|| Error::fatal(wolfssl_sys::WOLFSSL_BAD_PATH))?;
                let path = std::ffi::CString::new(path)
                    .map_err(|_| Error::fatal(wolfssl_sys::WOLFSSL_BAD_PATH))?;
                if is_dir {
                    // SAFETY: [`wolfSSL_CTX_load_verify_locations`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
                    // If not NULL, then the pointer passed as the path argument must be a valid NULL-terminated C-style string,
                    // which is guaranteed by the use of `std::ffi::CString::as_c_str()` here.
                    //
                    // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_locations
                    // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#gaf592c652b5d7a599ee511a394dfc488e
                    unsafe {
                        wolfSSL_CTX_load_verify_locations(
                            self.ctx.as_ptr(),
                            std::ptr::null(),
                            path.as_c_str().as_ptr(),
                        )
                    }
                } else {
                    // SAFETY: [`wolfSSL_CTX_load_verify_locations`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
                    // If not NULL, then the pointer passed as the path argument must be a valid NULL-terminated C-style string,
                    // which is guaranteed by the use of `std::ffi::CString::as_c_str()` here.
                    //
                    // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_locations
                    // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#gaf592c652b5d7a599ee511a394dfc488e
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
            .map_err(|_| Error::fatal(wolfssl_sys::WOLFSSL_FAILURE))?;

        // SAFETY: [`wolfSSL_CTX_set_cipher_list`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()` and
        // `list` parameter which should be a null terminated C string pointer which is guaranteed by
        // the use of `std::ffi::CString::as_c_str()` here.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_ctx_set_cipher_list
        // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#gafa55814f56bd7a36f4035d71b2b31832
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

    /// Wraps [`wolfSSL_CTX_set_groups`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_set_groups
    pub fn with_groups(self, groups: &[CurveGroup]) -> Result<Self> {
        let mut ffi_curves = groups.iter().map(|g| g.as_ffi() as i32).collect::<Vec<_>>();

        // SAFETY: [`wolfSSL_CTX_set_groups`][0] ([also][1]) requires
        // a valid `ctx` pointer from `wolfSSL_CTX_new()` and `groups`
        // parameter which should be a pointer to int with length
        // corresponding to the `count` argument which is guaranteed
        // by our use of a `Vec` here.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_set_groups
        // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#ga5bab039f79486d3ac31be72bc5f4e1e8
        let result = unsafe {
            wolfssl_sys::wolfSSL_CTX_set_groups(
                self.ctx.as_ptr(),
                ffi_curves.as_mut_ptr(),
                ffi_curves.len() as i32,
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
            // SAFETY: [`wolfSSL_CTX_use_certificate_buffer`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
            // The pointer given as the `in` argument must point to a region of `sz` bytes.
            // The values passed here are valid since they are derived from the same byte slice.
            //
            // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_buffer
            // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#gae424b3a63756ab805de5c43b67f4df4f
            Secret::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_use_certificate_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::Asn1File(path) => {
                let path = path
                    .to_str()
                    .ok_or_else(|| Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                let file = std::ffi::CString::new(path)
                    .map_err(|_| Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                // SAFETY: [`wolfSSL_CTX_use_certificate_file`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
                // The pointer passed as the path argument must be a valid NULL-terminated C-style string,
                // which is guaranteed by the use of `std::ffi::CString::as_c_str()` here.
                //
                // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_file
                // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#ga5a31292b75b4caa4462a3305d2615beb
                unsafe {
                    wolfSSL_CTX_use_certificate_file(
                        self.ctx.as_ptr(),
                        file.as_c_str().as_ptr(),
                        WOLFSSL_FILETYPE_ASN1,
                    )
                }
            }
            // SAFETY: [`wolfSSL_CTX_use_certificate_buffer`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
            // The pointer given as the `in` argument must point to a region of `sz` bytes.
            // The values passed here are valid since they are derived from the same byte slice.
            //
            // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_buffer
            // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#gae424b3a63756ab805de5c43b67f4df4f
            Secret::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_use_certificate_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            Secret::PemFile(path) => {
                let path = path
                    .to_str()
                    .ok_or_else(|| Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                let file = std::ffi::CString::new(path)
                    .map_err(|_| Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                // SAFETY: [`wolfSSL_CTX_use_certificate_file`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
                // The pointer passed as the path argument must be a valid NULL-terminated C-style string,
                // which is guaranteed by the use of `std::ffi::CString::as_c_str()` here.
                //
                // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_file
                // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#ga5a31292b75b4caa4462a3305d2615beb
                unsafe {
                    wolfSSL_CTX_use_certificate_file(
                        self.ctx.as_ptr(),
                        file.as_c_str().as_ptr(),
                        WOLFSSL_FILETYPE_PEM,
                    )
                }
            }
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
            // SAFETY: [`wolfSSL_CTX_use_PrivateKey_buffer`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
            // The pointer given as the `in` argument must point to a region of `sz` bytes.
            // The values passed here are valid since they are derived from the same byte slice.
            //
            // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_buffer
            // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#gaf88bd3ade7faefb028679f48ef64a237
            Secret::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_use_PrivateKey_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::Asn1File(path) => {
                let path = path
                    .to_str()
                    .ok_or_else(|| Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                let file = std::ffi::CString::new(path)
                    .map_err(|_| Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                // SAFETY: [`wolfSSL_CTX_use_PrivateKey_file`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
                // The pointer passed as the path argument must be a valid NULL-terminated C-style string,
                // which is guaranteed by the use of `std::ffi::CString::as_c_str()` here.
                //
                // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_file
                // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#gab80ef18b3232ebd19acab106b52feeb0
                unsafe {
                    wolfSSL_CTX_use_PrivateKey_file(
                        self.ctx.as_ptr(),
                        file.as_c_str().as_ptr(),
                        WOLFSSL_FILETYPE_ASN1,
                    )
                }
            }
            // SAFETY: [`wolfSSL_CTX_use_PrivateKey_buffer`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
            // The pointer given as the `in` argument must point to a region of `sz` bytes.
            // The values passed here are valid since they are derived from the same byte slice.
            //
            // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_buffer
            // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#gaf88bd3ade7faefb028679f48ef64a237
            Secret::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_use_PrivateKey_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            Secret::PemFile(path) => {
                let path = path
                    .to_str()
                    .ok_or_else(|| Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                let file = std::ffi::CString::new(path)
                    .map_err(|_| Error::fatal(wolfssl_sys::BAD_PATH_ERROR))?;
                // SAFETY: [`wolfSSL_CTX_use_PrivateKey_file`][0] ([also][1]) requires a valid `ctx` pointer from `wolfSSL_CTX_new()`.
                // The pointer passed as the path argument must be a valid NULL-terminated C-style string,
                // which is guaranteed by the use of `std::ffi::CString::as_c_str()` here.
                //
                // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_file
                // [1]: https://www.wolfssl.com/doxygen/group__CertsKeys.html#gab80ef18b3232ebd19acab106b52feeb0
                unsafe {
                    wolfSSL_CTX_use_PrivateKey_file(
                        self.ctx.as_ptr(),
                        file.as_c_str().as_ptr(),
                        WOLFSSL_FILETYPE_PEM,
                    )
                }
            }
        };

        if result == wolfssl_sys::WOLFSSL_SUCCESS {
            Ok(self)
        } else {
            Err(Error::fatal(result))
        }
    }

    /// Wraps `wolfSSL_CTX_UseSecureRenegotiation`
    ///
    /// NOTE: No official documentation available for this api from wolfssl
    pub fn with_secure_renegotiation(self) -> Result<Self> {
        // SAFETY: [`wolfSSL_CTX_UseSecureRenegotiation`][1] does not have proper documentation.
        // Based on the implementation, the only requirement is the context which is passed to this api has to be a valid `WOLFSSL_CTX`
        let result = unsafe { wolfssl_sys::wolfSSL_CTX_UseSecureRenegotiation(self.ctx.as_ptr()) };
        if result == wolfssl_sys::WOLFSSL_SUCCESS {
            Ok(self)
        } else {
            Err(Error::fatal(result))
        }
    }

    /// Wraps `wolfSSL_CTX_set_verify`[0]([also][1])
    // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_set_verify
    // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#ga26c623e093cf15f81cdfc3bb26682089
    pub fn with_verify_method(self, mode: SslVerifyMode) {
        // SAFETY: [`wolfSSL_CTX_set_verify`][0] ([also][1]) requires a valid `ctx` pointer
        // from `wolfSSL_CTX_new()`.
        // Third parameter `verify_callback` if valid, will be called when verification fails.
        // But we send `None` since we do not use this additional functionality
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_set_verify
        // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#ga26c623e093cf15f81cdfc3bb26682089
        unsafe { wolfssl_sys::wolfSSL_CTX_set_verify(self.ctx.as_ptr(), mode.into(), None) };
    }

    /// Finalizes a `WolfContext`.
    pub fn build(self) -> Context {
        Context {
            protocol: self.protocol,
            ctx: ContextPointer(self.ctx),
        }
    }
}

// Wrap a valid pointer to a [`wolfssl_sys::WOLFSSL_CONTEXT`] such that we can
// add traits such as `Send`.
pub(crate) struct ContextPointer(NonNull<wolfssl_sys::WOLFSSL_CTX>);

impl std::ops::Deref for ContextPointer {
    type Target = NonNull<wolfssl_sys::WOLFSSL_CTX>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// SAFETY: Per [Library Design][] under "Thread Safety"
//
// > Besides sharing WOLFSSL pointers, users must also take care to
// > completely initialize an WOLFSSL_CTX before passing the structure to
// > wolfSSL_new(). The same WOLFSSL_CTX can create multiple WOLFSSL
// > structs but the WOLFSSL_CTX is only read during wolfSSL_new()
// > creation and any future (or simultaneous changes) to the WOLFSSL_CTX
// > will not be reflected once the WOLFSSL object is created.
//
// > Again, multiple threads should synchronize writing access to a
// > WOLFSSL_CTX and it is advised that a single thread initialize the
// > WOLFSSL_CTX to avoid the synchronization and update problem
// > described above.
//
// This is consistent with the requirements for `Send`.
//
// The required syncronization when setting up the context is handled
// by the fact that [`ContextBuilder`] is not `Send`. In addition
// neither [`ContextPointer`] nor [`Context`] have any methods which
// offer writeable access.
//
// [Library Design]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html
unsafe impl Send for ContextPointer {}

// SAFETY: Per documentation quoted for `Send` above: once built the
// underlying `WOLFSSL_CONTEXT` is considered read-only. Our
// `ContextBuilder` enforces that the `Context` is completely built
// before a `Context` can be obtained and there are no mutable APIs on
// `Context` object once it is built.
unsafe impl Sync for ContextPointer {}

/// A wrapper around a `WOLFSSL_CTX`.
pub struct Context {
    protocol: Protocol,
    ctx: ContextPointer,
}

impl Context {
    /// Gets the underlying [`wolfssl_sys::WOLFSSL_CTX`] pointer that this is
    /// managing.
    ///
    /// # Safety:
    ///
    /// You must only use the resulting pointer for read operations
    /// (e.g. `wolfSSL_new`).
    pub(crate) unsafe fn ctx(&self) -> &ContextPointer {
        &self.ctx
    }

    /// Returns the Context's [`Protocol`].
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Creates a new SSL session using this underlying context.
    pub fn new_session<IOCB: IOCallbacks>(
        &self,
        config: SessionConfig<IOCB>,
    ) -> std::result::Result<Session<IOCB>, NewSessionError> {
        Session::new_from_context(self, config)
    }
}

impl Drop for Context {
    /// Invokes [`wolfSSL_CTX_free`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_free
    fn drop(&mut self) {
        // SAFETY: [`wolfSSL_CTX_free`][0] ([also][1]) takes pointer to `WOLFSSL_CTX` and frees it if the reference count becomes 0.
        // Documentation is not clear about when this reference count will be incremented. From implementation, it is
        // incremented in [`wolfSSL_set_SSL_CTX`][2] and [`wolfSSL_CTX_up_ref`][3], and we dont use these apis
        //
        // [0]: https://www.wolfssl.com/doxygen/group__Setup.html#gabe86939065276c9271a17d799860535d
        // [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_free
        // [2]: https://github.com/wolfSSL/wolfssl/blob/v5.6.3-stable/src/ssl.c#L31235
        // [3]: https://github.com/wolfSSL/wolfssl/blob/v5.6.3-stable/src/ssl.c#L1357
        unsafe { wolfssl_sys::wolfSSL_CTX_free(self.ctx.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        crate::wolf_init().unwrap();
        let _ = protocol.into_method_ptr().unwrap();
    }

    #[test]
    fn new() {
        ContextBuilder::new(Protocol::DtlsClient).unwrap();
    }

    #[test_case(true, true => true)]
    #[test_case(true, false => panics "Fatal(Other { what:")]
    #[test_case(false, false => false)]
    #[test_case(false, true => false)]
    fn try_when(whether: bool, ok: bool) -> bool {
        let mut called = false;
        let _ = ContextBuilder::new(Protocol::TlsClient)
            .unwrap()
            .try_when(whether, |b| {
                called = true;
                if ok {
                    Ok(b)
                } else {
                    Err(Error::fatal(wolfssl_sys::WOLFSSL_FAILURE))
                }
            })
            .unwrap();
        called
    }

    #[test_case(Some(true) => true)]
    #[test_case(Some(false) => panics "Fatal(Other { what:")]
    #[test_case(None => false)]
    fn try_some(whether: Option<bool>) -> bool {
        let mut called = false;
        let _ = ContextBuilder::new(Protocol::TlsClient)
            .unwrap()
            .try_when_some(whether, |b, ok| {
                called = true;
                if ok {
                    Ok(b)
                } else {
                    Err(Error::fatal(wolfssl_sys::WOLFSSL_FAILURE))
                }
            })
            .unwrap();
        called
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
    }

    #[test]
    fn set_cipher_list() {
        let _ = ContextBuilder::new(Protocol::DtlsClient)
            .unwrap()
            // This string might need to change depending on the flags
            // we built wolfssl with.
            .with_cipher_list("TLS13-CHACHA20-POLY1305-SHA256")
            .unwrap();
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
    }

    #[test]
    fn set_secure_renegotiation() {
        let _ = ContextBuilder::new(Protocol::TlsClient)
            .unwrap()
            .with_secure_renegotiation()
            .unwrap();
    }

    #[test_case(SslVerifyMode::SslVerifyNone)]
    #[test_case(SslVerifyMode::SslVerifyPeer)]
    #[test_case(SslVerifyMode::SslVerifyFailIfNoPeerCert)]
    #[test_case(SslVerifyMode::SslVerifyFailExceptPsk)]
    fn set_verify_method(mode: SslVerifyMode) {
        ContextBuilder::new(Protocol::TlsClient)
            .unwrap()
            .with_verify_method(mode);
    }

    #[test]
    fn register_io_callbacks() {
        let _ = ContextBuilder::new(Protocol::TlsClient).unwrap().build();
    }
}
