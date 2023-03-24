use wolfssl_sys::WOLFSSL;

use thiserror::Error;

// Note that this accepts an `unsigned long` instead of an `int`.
//
// Which is odd, because we're supposed to pass this the result of
// `wolfSSL_get_error`, which returns a `c_int`
fn wolf_get_error_string(raw_err: ::std::os::raw::c_ulong) -> String {
    let mut buffer = vec![0u8; wolfssl_sys::WOLFSSL_MAX_ERROR_SZ as usize];
    unsafe {
        wolfssl_sys::wolfSSL_ERR_error_string(
            raw_err,
            // note that we are asked for a `char *`, but the
            // following `from_utf8` asks for a Vec<u8>
            buffer.as_mut_slice().as_mut_ptr() as *mut i8,
        );
    }
    String::from_utf8(buffer)
        .expect("wolfSSL_ERR_error_string returned invalid ASCII")
        .trim_end_matches(char::from(0))
        .to_string()
}

#[derive(Error, Debug)]
pub enum WolfError {
    #[error("WolfSSL wants to read in data")]
    WantRead,
    #[error("WolfSSL wants to write data out")]
    WantWrite,
    #[error("unknown: {what}")]
    Unknown { what: String, code: usize },
}

impl WolfError {
    pub(crate) fn get_error(ssl: *mut WOLFSSL, ret: i32) -> Self {
        let err = unsafe { wolfssl_sys::wolfSSL_get_error(ssl, ret) };
        WolfError::from(err)
    }
}

impl std::convert::From<std::os::raw::c_int> for WolfError {
    fn from(code: std::os::raw::c_int) -> Self {
        match code {
            wolfssl_sys::WOLFSSL_ERROR_WANT_READ => Self::WantRead,
            wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE => Self::WantWrite,
            x => {
                let what = wolf_get_error_string(x as std::os::raw::c_ulong);
                Self::Unknown {
                    what,
                    code: x as usize,
                }
            }
        }
    }
}

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
