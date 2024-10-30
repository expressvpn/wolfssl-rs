use std::ffi::c_int;

use bytes::Bytes;
use thiserror::Error;
use wolfssl_sys::wolfSSL_ErrorCodes_DOMAIN_NAME_MISMATCH as WOLFSSL_ERROR_DOMAIN_NAME_MISMATCH;
use wolfssl_sys::wolfSSL_ErrorCodes_DUPLICATE_MSG_E as WOLFSSL_ERROR_DUPLICATE_MSG_E;

/// The `Result::Ok` for a non-blocking operation.
#[derive(Debug)]
pub enum Poll<T> {
    /// Underlying IO operations are still ongoing. No output has been generated
    /// yet. A write is pending
    PendingWrite,
    /// Underlying IO operations are still ongoing. No output has been generated
    /// yet. A write is pending
    PendingRead,
    /// An output has been generated.
    Ready(T),
    /// When under secure renegotiation, WolfSSL can now sometimes emit an
    /// `APP_DATA_READY` code, meaning that it has received application data
    /// during this renegotiation. This variant contains this information.
    AppData(Bytes),
}

#[derive(Clone, Error, Debug)]
/// The failure result of an operation.
pub enum Error {
    /// During secure renegotiation, if application data is found, we must call
    /// `wolfssl_read` to extract the data. If that `wolfssl_read` call fails,
    /// this error will be generated.
    #[error("App Data: {0}")]
    AppData(ErrorKind),
    /// Top-level errors from WolfSSL API invocations.
    #[error("Fatal: {0}")]
    Fatal(ErrorKind),
}

impl Error {
    /// Construct a fatal error
    pub(crate) fn fatal(code: c_int) -> Self {
        Self::Fatal(ErrorKind::from(code))
    }

    /// Get error kind
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::AppData(e) => e,
            Error::Fatal(e) => e,
        }
        .clone()
    }
}

/// Extracts an error message given a wolfssl error enum.
/// Abstraction over WolfSSL errors
#[derive(Clone, Debug, Error)]
pub enum ErrorKind {
    /// Domain name mismatch error)
    #[error("Domain name mismatch")]
    DomainNameMismatch,
    /// Duplicate message error
    #[error("Duplicate message error")]
    DuplicateMessage,
    /// All other wolfssl fatal errors
    #[error("code: {code}, what: {what}")]
    Other {
        /// Textual representation of error code
        what: String,
        /// Error code
        code: c_int,
    },
}

impl std::convert::From<c_int> for ErrorKind {
    // Not all errors are fatal. Since the errors are fundamentally C-style
    // enums, the most we can do is to just check that only fatal errors get
    // constructed.
    fn from(code: c_int) -> Self {
        let this = match code {
            WOLFSSL_ERROR_DOMAIN_NAME_MISMATCH => Self::DomainNameMismatch,
            WOLFSSL_ERROR_DUPLICATE_MSG_E => Self::DuplicateMessage,
            _other => Self::Other {
                what: wolf_error_string(code as std::ffi::c_ulong),
                code,
            },
        };

        debug_assert!(
            !matches!(
                this,
                Self::Other {
                    code: wolfssl_sys::WOLFSSL_ERROR_WANT_READ_c_int
                        | wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE_c_int
                        | wolfssl_sys::WOLFSSL_SUCCESS_c_int,
                    ..
                }
            ),
            "Attempting to construct a `ErrorKind` from a non-error code {code}",
            code = code,
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

    // SAFETY:
    // [`wolfSSL_ERR_error_string()`][0] ([also][1]) is documented to store at most `WOLFSSL_MAX_ERROR_SZ` bytes,
    // so `buffer` is appropriately sized.
    // Note that `wolfSSL_ERR_error_string()` is documented to use a static buffer (shared between threads,
    // and thus non-reentrant) on failure, however it only does so if no buffer is provided as an argument.
    // Since we provide a buffer we assume the static buffer can never be used in practice.
    //
    // [0]: https://www.wolfssl.com/doxygen/group__Debug.html#ga91d8474ba8abcf3fe594928056834993
    // [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_err_error_string
    unsafe {
        wolfssl_sys::wolfSSL_ERR_error_string(
            raw_err,
            // note that we are asked for a `char *`, but the
            // following `from_utf8` asks for a Vec<u8>
            buffer.as_mut_slice().as_mut_ptr() as *mut std::os::raw::c_char,
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
