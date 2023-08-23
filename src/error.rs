use std::ffi::c_int;

use bytes::Bytes;
use thiserror::Error;

#[derive(Debug)]
pub enum Poll<T> {
    /// Underlying IO operations are still ongoing. No output has been generated
    /// yet.
    Pending,
    /// An output has been generated.
    Ready(T),
    /// When under secure renegotiation, WolfSSL can now sometimes emit an
    /// `APP_DATA_READY` code, meaning that it has received application data
    /// during this renegotiation. This variant contains this information.
    AppData(Bytes),
}

#[derive(Error, Debug)]
pub enum Error {
    /// During secure renegotiation, if application data is found, we must call
    /// `wolfssl_read` to extract the data. If that `wolfssl_read` call fails,
    /// this error will be generated.
    #[error("App Data: {0}")]
    AppData(FatalError),
    /// Top-level errors from WolfSSL API invocations.
    #[error("Fatal: {0}")]
    Fatal(FatalError),
}

impl Error {
    pub fn fatal(code: c_int) -> Self {
        Self::Fatal(FatalError::from(code))
    }

    pub fn app_data(code: c_int) -> Self {
        Self::AppData(FatalError::from(code))
    }
}

/// Extracts an error message given a wolfssl error enum.
#[derive(Error, Debug)]
#[error("code: {code}, what: {what}")]
pub struct FatalError {
    what: String,
    code: c_int,
}

impl std::convert::From<c_int> for FatalError {
    // Not all errors are fatal. Since the errors are fundamentally C-style
    // enums, the most we can do is to just check that only fatal errors get
    // constructed.
    fn from(code: c_int) -> Self {
        let this = Self {
            what: wolf_error_string(code as std::ffi::c_ulong),
            code,
        };

        debug_assert!(
            !matches!(
                this,
                Self {
                    code: wolfssl_sys::WOLFSSL_ERROR_WANT_READ
                        | wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE
                        | wolfssl_sys::WOLFSSL_SUCCESS,
                        // | wolfssl_sys::WOLFSSL_ERROR_NONE, // since WOLFSSL_FAILURE also uses this value
                    ..
                }
            ),
            "Attempting to construct a `FatalError` from a non-fatal error code {code}, with error message {what}",
            code = this.code,
            what = this.what
        );

        this
    }
}

/// Describes an outcome that is asynchronous. Certain methods in WolfSSL can
/// return a `WANT_READ`/`WANT_WRITE`-ish error, which WolfSSL does not consider
/// fatal, and indicates that the caller should retry again (usually after doing
/// some form of rectification like handling the IO buffers)
pub type PollResult<T> = std::result::Result<Poll<T>, Error>;

/// Describes an outcome that is synchronous.
pub type Result<T> = std::result::Result<T, Error>;

/// Converts a WolfSSL error code to a string
// Note that this accepts an `unsigned long` instead of an `int`.
//
// Which is odd, because we're supposed to pass this the result of
// `wolfSSL_get_error`, which returns a `c_int`
fn wolf_error_string(raw_err: std::ffi::c_ulong) -> String {
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

#[cfg(test)]
mod wolf_error {
    use super::*;

    #[test]
    fn wolf_error_string_check_string() {
        let s = wolf_error_string(wolfssl_sys::WOLFSSL_ERROR_WANT_READ as std::ffi::c_ulong);
        assert_eq!(s, "non-blocking socket wants data to be read");
    }
}
