use thiserror::Error;

// Note that this accepts an `unsigned long` instead of an `int`.
//
// Which is odd, because we're supposed to pass this the result of
// `wolfSSL_get_error`, which returns a `c_int`
#[allow(dead_code)]
pub fn wolf_error_string(raw_err: ::std::os::raw::c_ulong) -> String {
    let mut buffer = vec![0u8; wolfssl_sys::WOLFSSL_MAX_ERROR_SZ as usize];
    unsafe {
        wolfssl_sys::wolfSSL_ERR_error_string(
            raw_err,
            // note that we are asked for a `char *`, but the
            // following `from_utf8` asks for a Vec<u8>
            buffer.as_mut_slice().as_mut_ptr() as *mut i8,
        );
    }
    String::from_utf8_lossy(&buffer)
        .trim_end_matches(char::from(0))
        .to_string()
}

/// Return error values for [`crate::wolf_init`]
#[derive(Error, Debug)]
pub enum WolfInitError {
    #[error("BAD_MUTEX_E")]
    Mutex,
    #[error("WC_INIT_E")]
    WolfCrypt,
}

/// Return error values for [`crate::wolf_cleanup`]
#[derive(Error, Debug)]
pub enum WolfCleanupError {
    #[error("BAD_MUTEX_E")]
    Mutex,
}

/// Possible errors returnable by
/// [`wolfSSL_CTX_load_verify_buffer`][0] and [`wolfSSL_CTX_load_verify_locations`][1]
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_buffer
/// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_locations
#[derive(Error, Debug)]
pub enum LoadRootCertificateError {
    #[error("SSL_FAILURE")]
    Failure,
    #[error("SSL_BAD_FILETYPE")]
    BadFiletype,
    #[error("SSL_BAD_FILE")]
    BadFile,
    #[error("MEMORY_E")]
    Memory,
    #[error("ASN_INPUT_E")]
    AsnInput,
    #[error("ASN_BEFORE_DATE_E")]
    AsnBeforeDate,
    #[error("ASN_AFTER_DATE_E")]
    AsnAfterDate,
    #[error("BUFFER_E")]
    Buffer,
    #[error("BAD_PATH_ERROR")]
    Path,
    #[error("Unknown: {0}")]
    Other(i64),
}

use std::os::raw::c_int;

impl From<c_int> for LoadRootCertificateError {
    fn from(value: c_int) -> Self {
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
            e => Self::Other(e as i64),
        }
    }
}
