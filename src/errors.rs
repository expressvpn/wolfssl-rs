/// Return error values for [`wolf_init`]
#[derive(Debug)]
pub enum WolfInitError {
    /// Corresponds with `BAD_MUTEX_E`
    Mutex,
    /// Corresponds with `WC_INIT_E`
    WolfCrypt,
}

/// Return error values for [`wolf_cleanup`]
#[derive(Debug)]
pub enum WolfCleanupError {
    /// Corresponds with `BAD_MUTEX_E`
    Mutex,
}

/// Possible errors returnable by
/// [`wolfSSL_CTX_load_verify_buffer`][0] and [`wolfSSL_CTX_load_verify_locations`][1]
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_buffer
/// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_locations
#[derive(Debug)]
pub enum LoadRootCertificateError {
    /// `SSL_FAILURE`
    Failure,
    /// `SSL_BAD_FILETYPE`
    BadFiletype,
    /// `SSL_BAD_FILE`
    BadFile,
    /// `MEMORY_E`
    Memory,
    /// `ASN_INPUT_E`
    AsnInput,
    /// `ASN_BEFORE_DATE_E`
    AsnBeforeDate,
    /// `ASN_AFTER_DATE_E`
    AsnAfterDate,
    /// `BUFFER_E`
    Buffer,
    /// `BAD_PATH_ERROR`
    Path,
    /// Error values outside of what was documented
    Other(i64),
}

impl From<i32> for LoadRootCertificateError {
    fn from(value: std::os::raw::c_int) -> Self {
        match value {
            wolfssl_sys::WOLFSSL_BAD_FILETYPE => Self::BadFiletype,
            wolfssl_sys::WOLFSSL_BAD_FILE => Self::BadFile,
            wolfssl_sys::MEMORY_E => Self::Memory,
            wolfssl_sys::ASN_INPUT_E => Self::AsnInput,
            wolfssl_sys::BUFFER_E => Self::Buffer,
            wolfssl_sys::WOLFSSL_FAILURE => Self::Failure,
            wolfssl_sys::ASN_AFTER_DATE_E => Self::AsnAfterDate,
            wolfssl_sys::ASN_BEFORE_DATE_E => Self::AsnBeforeDate,
            wolfssl_sys::BAD_PATH_ERROR => Self::Path,
            e => Self::Other(e as i64), // e => panic!("Undocumented return value: got {e}"),
        }
    }
}
