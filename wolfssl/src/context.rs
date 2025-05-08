use crate::{
    callback::IOCallbacks,
    error::{Error, Result},
    ssl::{Session, SessionConfig},
    CurveGroup, Method, NewSessionError, RootCertificate, Secret, SslVerifyMode,
};
use std::{
    ffi::{c_void, CStr, CString},
    fmt::Debug,
    os::raw::{c_char, c_int, c_uint},
    ptr::NonNull,
    sync::Arc,
};
use thiserror::Error;

/// Produces a [`Context`] once built.
#[derive(Debug)]
pub struct ContextBuilder {
    ctx: NonNull<wolfssl_sys::WOLFSSL_CTX>,
    method: Method,
    pre_shared_key_callbacks: Option<Arc<dyn PreSharedKeyCallbacks>>,
}

/// Error creating a [`ContextBuilder`] object.
#[derive(Error, Debug)]
pub enum NewContextBuilderError {
    /// Failed to initialize WolfSSL
    #[error("Failed to initialize WolfSSL: {0}")]
    InitFailed(Error),

    /// Failed to turn `Method` into a `wolfssl_sys::WOLFSSL_METHOD`
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
    pub fn new(method: Method) -> std::result::Result<Self, NewContextBuilderError> {
        crate::wolf_init().map_err(NewContextBuilderError::InitFailed)?;

        let method_fn = method
            .into_method_ptr()
            .ok_or(NewContextBuilderError::MethodFailed)?;

        // SAFETY: [`wolfSSL_CTX_new`][0] is documented to get pointer to a valid `WOLFSSL_METHOD` structure which is created using one of the `wolfSSLvXX_XXXX_method()`.
        // `Method::into_method_ptr` function returns a pointer `wolfSSLvXX_XXXX_method()`
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_new
        let ctx = unsafe { wolfssl_sys::wolfSSL_CTX_new(method_fn.as_ptr()) };
        let ctx = NonNull::new(ctx).ok_or(NewContextBuilderError::CreateFailed)?;

        Ok(Self {
            ctx,
            method,
            pre_shared_key_callbacks: None,
        })
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
                    buf.len() as std::os::raw::c_long,
                    WOLFSSL_FILETYPE_ASN1 as c_int,
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
                    buf.len() as std::os::raw::c_long,
                    WOLFSSL_FILETYPE_PEM as c_int,
                )
            },
            RootCertificate::PemFileOrDirectory(path) => {
                let is_dir = path.is_dir();
                let path = path.to_str().ok_or_else(|| {
                    Error::fatal(wolfssl_sys::wolfSSL_ErrorCodes_WOLFSSL_BAD_PATH)
                })?;
                let path = std::ffi::CString::new(path)
                    .map_err(|_| Error::fatal(wolfssl_sys::wolfSSL_ErrorCodes_WOLFSSL_BAD_PATH))?;
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

        if result == wolfssl_sys::WOLFSSL_SUCCESS as c_int {
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
            .map_err(|_| Error::fatal(wolfssl_sys::WOLFSSL_FAILURE as c_int))?;

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

        if result == wolfssl_sys::WOLFSSL_SUCCESS as c_int {
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

        if result == wolfssl_sys::WOLFSSL_SUCCESS as c_int {
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
                    buf.len() as std::os::raw::c_long,
                    WOLFSSL_FILETYPE_ASN1 as c_int,
                )
            },
            Secret::Asn1File(path) => {
                let path = path.to_str().ok_or_else(|| {
                    Error::fatal(wolfssl_sys::wolfCrypt_ErrorCodes_BAD_PATH_ERROR)
                })?;
                let file = std::ffi::CString::new(path)
                    .map_err(|_| Error::fatal(wolfssl_sys::wolfCrypt_ErrorCodes_BAD_PATH_ERROR))?;
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
                        WOLFSSL_FILETYPE_ASN1 as c_int,
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
                    buf.len() as std::os::raw::c_long,
                    WOLFSSL_FILETYPE_PEM as c_int,
                )
            },
            Secret::PemFile(path) => {
                let path = path.to_str().ok_or_else(|| {
                    Error::fatal(wolfssl_sys::wolfCrypt_ErrorCodes_BAD_PATH_ERROR)
                })?;
                let file = std::ffi::CString::new(path)
                    .map_err(|_| Error::fatal(wolfssl_sys::wolfCrypt_ErrorCodes_BAD_PATH_ERROR))?;
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
                        WOLFSSL_FILETYPE_PEM as c_int,
                    )
                }
            }
        };

        if result == wolfssl_sys::WOLFSSL_SUCCESS as c_int {
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
                    buf.len() as std::os::raw::c_long,
                    WOLFSSL_FILETYPE_ASN1 as c_int,
                )
            },
            Secret::Asn1File(path) => {
                let path = path.to_str().ok_or_else(|| {
                    Error::fatal(wolfssl_sys::wolfCrypt_ErrorCodes_BAD_PATH_ERROR)
                })?;
                let file = std::ffi::CString::new(path)
                    .map_err(|_| Error::fatal(wolfssl_sys::wolfCrypt_ErrorCodes_BAD_PATH_ERROR))?;
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
                        WOLFSSL_FILETYPE_ASN1 as c_int,
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
                    buf.len() as std::os::raw::c_long,
                    WOLFSSL_FILETYPE_PEM as c_int,
                )
            },
            Secret::PemFile(path) => {
                let path = path.to_str().ok_or_else(|| {
                    Error::fatal(wolfssl_sys::wolfCrypt_ErrorCodes_BAD_PATH_ERROR)
                })?;
                let file = std::ffi::CString::new(path)
                    .map_err(|_| Error::fatal(wolfssl_sys::wolfCrypt_ErrorCodes_BAD_PATH_ERROR))?;
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
                        WOLFSSL_FILETYPE_PEM as c_int,
                    )
                }
            }
        };

        if result == wolfssl_sys::WOLFSSL_SUCCESS as c_int {
            Ok(self)
        } else {
            Err(Error::fatal(result))
        }
    }

    unsafe extern "C" fn psk_server_callback(
        ssl: *mut wolfssl_sys::WOLFSSL,
        identity_ptr: *const c_char,
        key_output_ptr: *mut u8,
        max_key_length_c_uint: c_uint,
    ) -> c_uint {
        debug_assert!(!ssl.is_null());
        debug_assert!(!identity_ptr.is_null()); // TODO: verify, can this be null in some cases?
        debug_assert!(!key_output_ptr.is_null());

        // SAFETY: identity_ptr is in fact a C string
        let identity: &CStr = unsafe { CStr::from_ptr(identity_ptr) };
        let max_key_length: usize = max_key_length_c_uint.try_into().unwrap();

        // SAFETY: `wolfSSL_get_psk_callback_ctx` is undocumented, but the implementation simply
        // gets a field out of the WOLFSSL object.
        let stored_cbs_ptr_ptr: *const c_void =
            unsafe { wolfssl_sys::wolfSSL_get_psk_callback_ctx(ssl) };
        // SAFETY: This is written in `Session::new_from_wolfssl_pointer` as a pointer to the
        // contents of an Arc, so should have stable address. The Arc is stored until the end of the
        // session and hence should be alive.
        let stored_cbs: &Arc<dyn PreSharedKeyCallbacks> =
            unsafe { &*(stored_cbs_ptr_ptr as *const Arc<dyn PreSharedKeyCallbacks>) };

        let maybe_key = stored_cbs.psk_server_callback(identity, max_key_length);
        match maybe_key {
            Some(key) => {
                assert!(
                    key.len() <= max_key_length,
                    "Key length {} returned by server callback was longer than maximum {}",
                    key.len(),
                    max_key_length
                );
                // SAFETY: we've verified that the vec length is <= max_key_length, so we won't overrun
                // the buffer provided to us.
                unsafe { std::ptr::copy(key.as_ptr(), key_output_ptr, key.len()) };
                key.len().try_into().unwrap()
            }
            None => 0,
        }
    }

    unsafe extern "C" fn psk_client_callback(
        ssl: *mut wolfssl_sys::WOLFSSL,
        _hint: *const c_char,
        identity_output: *mut c_char,
        max_identity_length_c_uint: c_uint,
        key_output: *mut u8,
        max_key_length_c_uint: c_uint,
    ) -> c_uint {
        debug_assert!(!ssl.is_null());
        debug_assert!(!identity_output.is_null());
        debug_assert!(!key_output.is_null());

        let max_identity_length: usize = max_identity_length_c_uint.try_into().unwrap();
        let max_key_length: usize = max_key_length_c_uint.try_into().unwrap();

        // SAFETY: See `psk_server_callback`
        let stored_cbs_ptr_ptr: *const c_void =
            unsafe { wolfssl_sys::wolfSSL_get_psk_callback_ctx(ssl) };
        // SAFETY: See `psk_server_callback`
        let stored_cbs: &Arc<dyn PreSharedKeyCallbacks> =
            unsafe { &*(stored_cbs_ptr_ptr as *const Arc<dyn PreSharedKeyCallbacks>) };

        let maybe_result = stored_cbs.psk_client_callback(max_identity_length, max_key_length);
        match maybe_result {
            Some(PreSharedKeyClientCallbackResult { identity, key }) => {
                // TODO verify that max_identity_length is without nul byte
                assert!(
                    identity.count_bytes() <= max_identity_length,
                    "Identity length {} was not less than maximum {}",
                    identity.count_bytes(),
                    max_identity_length
                );
                assert!(
                    key.len() <= max_key_length,
                    "Key length {} was not less than maximum {}",
                    key.len(),
                    max_key_length
                );

                // SAFETY: See `psk_server_callback`. The +1 is to include the nul terminator.
                // TODO verify that the nul terminator is not included in max_identity_length
                unsafe { std::ptr::copy(key.as_ptr(), key_output, key.len()) };
                // SAFETY: See immediately above. +1 to account for nul terminator.
                unsafe {
                    std::ptr::copy(
                        identity.as_ptr(),
                        identity_output,
                        identity.count_bytes() + 1,
                    )
                };

                key.len().try_into().unwrap()
            }
            None => 0,
        }
    }

    /// Use a pre-shared key for authentication
    ///
    /// Calls either `wolfSSL_CTX_set_psk_server_callback` or `wolfSSL_CTX_set_psk_client_callback`
    /// appropriately using a provided callback. Later, during session constrtuction, calls
    /// `wolfSSL_set_psk_callback_ctx` to point to make the key accessible in the callback.
    pub fn with_pre_shared_key(self, psk: &[u8]) -> Self {
        self.with_pre_shared_key_callbacks(Arc::new(FixedPskCallbacks::new(psk)))
    }

    /// Use pre-shared key callbacks for authentication
    ///
    /// Install custom client and server callbacks for pre-shared-key authentication.
    pub fn with_pre_shared_key_callbacks(self, callbacks: Arc<dyn PreSharedKeyCallbacks>) -> Self {
        if self.method.is_server() {
            // SAFETY: `wolfSSL_CTX_set_psk_server_callback` isn't properly documented. It seems the
            // only requirement is that the context is valid and the callback will be alive
            // throughout the lifetime of the context and any created sessions; our callbacks are
            // &'static.
            unsafe {
                wolfssl_sys::wolfSSL_CTX_set_psk_server_callback(
                    self.ctx.as_ptr(),
                    Some(Self::psk_server_callback),
                );
            };
        } else {
            // SAFETY: See above.
            unsafe {
                wolfssl_sys::wolfSSL_CTX_set_psk_client_callback(
                    self.ctx.as_ptr(),
                    Some(Self::psk_client_callback),
                );
            };
        };

        Self {
            pre_shared_key_callbacks: Some(callbacks.into()),
            ..self
        }
    }

    /// Wraps `wolfSSL_CTX_UseSecureRenegotiation`
    ///
    /// NOTE: No official documentation available for this api from wolfssl
    pub fn with_secure_renegotiation(self) -> Result<Self> {
        // SAFETY: [`wolfSSL_CTX_UseSecureRenegotiation`][1] does not have proper documentation.
        // Based on the implementation, the only requirement is the context which is passed to this api has to be a valid `WOLFSSL_CTX`
        let result = unsafe { wolfssl_sys::wolfSSL_CTX_UseSecureRenegotiation(self.ctx.as_ptr()) };
        if result == wolfssl_sys::WOLFSSL_SUCCESS as c_int {
            Ok(self)
        } else {
            Err(Error::fatal(result))
        }
    }

    /// Wraps `wolfSSL_CTX_set_verify`[0]([also][1])
    // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_set_verify
    // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#ga26c623e093cf15f81cdfc3bb26682089
    pub fn with_verify_method(self, mode: SslVerifyMode) -> Self {
        // SAFETY: [`wolfSSL_CTX_set_verify`][0] ([also][1]) requires a valid `ctx` pointer
        // from `wolfSSL_CTX_new()`.
        // Third parameter `verify_callback` if valid, will be called when verification fails.
        // But we send `None` since we do not use this additional functionality
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_set_verify
        // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#ga26c623e093cf15f81cdfc3bb26682089
        unsafe { wolfssl_sys::wolfSSL_CTX_set_verify(self.ctx.as_ptr(), mode.into(), None) };
        self
    }

    /// Finalizes a `WolfContext`.
    pub fn build(self) -> Context {
        Context {
            method: self.method,
            ctx: ContextPointer(self.ctx),
            pre_shared_key_callbacks: self.pre_shared_key_callbacks,
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

// Wrap a valid pointer to a [`wolfssl_sys::WOLFSSL`] such that we can
// add traits such as `Send`.
pub(crate) struct WolfsslPointer(NonNull<wolfssl_sys::WOLFSSL>);

impl WolfsslPointer {
    pub(crate) fn as_ptr(&mut self) -> *mut wolfssl_sys::WOLFSSL {
        self.0.as_ptr()
    }
}

// SAFETY: Per [Library Design][] under "Thread Safety"
//
// > A client may share an WOLFSSL object across multiple threads but
// > access must be synchronized, i.e., trying to read/write at the same
// > time from two different threads with the same SSL pointer is not
// > supported.
//
// This is consistent with the requirements for `Send`. The required
// syncronization is handled by requiring `&mut self` in all relevant
// methods.
//
// [Library Design]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html
unsafe impl Send for WolfsslPointer {}

/// A wrapper around a `WOLFSSL_CTX`.
pub struct Context {
    method: Method,
    ctx: ContextPointer,
    pre_shared_key_callbacks: Option<Arc<dyn PreSharedKeyCallbacks>>,
}

impl Context {
    /// Returns the Context's [`Method`].
    pub fn method(&self) -> Method {
        self.method
    }

    /// Creates a new SSL session using this underlying context.
    pub fn new_session<IOCB: IOCallbacks>(
        &self,
        config: SessionConfig<IOCB>,
    ) -> std::result::Result<Session<IOCB>, NewSessionError> {
        // SAFETY: [`wolfSSL_new`][0] ([also][1]) needs a valid `wolfssl_sys::WOLFSSL_CTX` pointer as per documentation
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_new
        // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#gaa37dc22775da8f6a3b5c149d5dfd6e1c
        let ptr = unsafe { wolfssl_sys::wolfSSL_new(self.ctx.as_ptr()) };

        let ssl = WolfsslPointer(NonNull::new(ptr).ok_or(NewSessionError::CreateFailed)?);

        Session::new_from_wolfssl_pointer(ssl, config, self.pre_shared_key_callbacks.clone())
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

/// Returned from the client callback in [PreSharedKeyCallbacks]
pub struct PreSharedKeyClientCallbackResult {
    /// Should be an empty string if you don't need multiple identities
    pub identity: CString,
    /// The pre-shared key itself.
    pub key: Vec<u8>,
}

/// Callbacks that are used to provide a pre-shared key to wolfSSL.
pub trait PreSharedKeyCallbacks: Debug {
    /// Called on the client before starting the connection.
    ///
    /// The installed wolfSSL callback will return 0 if None is returned from the Rust callback,
    /// which means "fail". The wolfSSL docs are unclear what happens when the callback fails in
    /// this way.
    fn psk_client_callback(
        &self,
        max_identity_length: usize,
        max_key_length: usize,
    ) -> Option<PreSharedKeyClientCallbackResult>;

    /// Called on the server after receiving the client hello.
    ///
    /// Receives the identity set in the client callback (which defaults to empty string). Should put the key into the key_buf.
    fn psk_server_callback(&self, identity: &CStr, max_key_length: usize) -> Option<Vec<u8>>;
}

/// An implementation of PreSharedKeyCallbacks that uses a fixed buffer as the pre-shared key, which
/// is the most common usecase for pre shared keys.
#[derive(Debug)]
struct FixedPskCallbacks {
    key: Vec<u8>,
}

impl FixedPskCallbacks {
    /// Construct a FixedPskCallbacks object that will always use the given key.
    fn new<T: Into<Vec<u8>>>(key: T) -> FixedPskCallbacks {
        FixedPskCallbacks { key: key.into() }
    }
}

impl PreSharedKeyCallbacks for FixedPskCallbacks {
    fn psk_client_callback(
        &self,
        _max_identity_length: usize,
        max_key_length: usize,
    ) -> Option<PreSharedKeyClientCallbackResult> {
        if self.key.len() > max_key_length {
            return None;
        }

        Some(PreSharedKeyClientCallbackResult {
            identity: c"".into(),
            key: self.key.clone(),
        })
    }

    fn psk_server_callback(&self, _identity: &CStr, max_key_length: usize) -> Option<Vec<u8>> {
        if self.key.len() > max_key_length {
            return None;
        }

        Some(self.key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(Method::DtlsClient)]
    #[test_case(Method::DtlsClientV1_2)]
    #[test_case(Method::DtlsServer)]
    #[test_case(Method::DtlsServerV1_2)]
    #[test_case(Method::TlsClient)]
    #[test_case(Method::TlsClientV1_2)]
    #[test_case(Method::TlsClientV1_3)]
    #[test_case(Method::TlsServer)]
    #[test_case(Method::TlsServerV1_2)]
    #[test_case(Method::TlsServerV1_3)]
    fn wolfssl_context_new(method: Method) {
        crate::wolf_init().unwrap();
        let _ = method.into_method_ptr().unwrap();
    }

    #[test]
    fn new() {
        ContextBuilder::new(Method::DtlsClient).unwrap();
    }

    #[test_case(true, true => true)]
    #[test_case(true, false => panics "Fatal(Other { what:")]
    #[test_case(false, false => false)]
    #[test_case(false, true => false)]
    fn try_when(whether: bool, ok: bool) -> bool {
        let mut called = false;
        let _ = ContextBuilder::new(Method::TlsClient)
            .unwrap()
            .try_when(whether, |b| {
                called = true;
                if ok {
                    Ok(b)
                } else {
                    Err(Error::fatal(wolfssl_sys::WOLFSSL_FAILURE as c_int))
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
        let _ = ContextBuilder::new(Method::TlsClient)
            .unwrap()
            .try_when_some(whether, |b, ok| {
                called = true;
                if ok {
                    Ok(b)
                } else {
                    Err(Error::fatal(wolfssl_sys::WOLFSSL_FAILURE as c_int))
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

        let _ = ContextBuilder::new(Method::TlsClient)
            .unwrap()
            .with_root_certificate(cert)
            .unwrap();
    }

    #[test]
    fn set_cipher_list() {
        let _ = ContextBuilder::new(Method::DtlsClient)
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

        let _ = ContextBuilder::new(Method::TlsClient)
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

        let _ = ContextBuilder::new(Method::TlsClient)
            .unwrap()
            .with_private_key(key)
            .unwrap();
    }

    #[test]
    fn set_secure_renegotiation() {
        let _ = ContextBuilder::new(Method::TlsClient)
            .unwrap()
            .with_secure_renegotiation()
            .unwrap();
    }

    #[test_case(SslVerifyMode::SslVerifyNone)]
    #[test_case(SslVerifyMode::SslVerifyPeer)]
    #[test_case(SslVerifyMode::SslVerifyFailIfNoPeerCert)]
    #[test_case(SslVerifyMode::SslVerifyFailExceptPsk)]
    fn set_verify_method(mode: SslVerifyMode) {
        ContextBuilder::new(Method::TlsClient)
            .unwrap()
            .with_verify_method(mode);
    }

    #[test]
    fn register_io_callbacks() {
        let _ = ContextBuilder::new(Method::TlsClient).unwrap().build();
    }
}
