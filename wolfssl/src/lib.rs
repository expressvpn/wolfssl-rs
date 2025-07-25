//! The `wolfssl` crate is designed to be a Rust layer built on top of
//! the `wolfssl-sys` crate (a C passthrough crate).

mod aes256;
mod callback;
mod chacha20_poly1305;
mod context;
mod debug;
mod error;
mod rng;
mod ssl;

pub use aes256::*;
pub use callback::*;
pub use chacha20_poly1305::*;
pub use context::*;
pub use rng::*;
pub use ssl::*;

pub use error::{Error, ErrorKind, Poll, Result};

#[cfg(feature = "debug")]
pub use debug::*;
use wolfssl_sys::{
    WOLFSSL_VERIFY_FAIL_EXCEPT_PSK_c_int as WOLFSSL_VERIFY_FAIL_EXCEPT_PSK,
    WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT_c_int as WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
    WOLFSSL_VERIFY_NONE_c_int as WOLFSSL_VERIFY_NONE,
    WOLFSSL_VERIFY_PEER_c_int as WOLFSSL_VERIFY_PEER,
};

use std::{os::raw::c_int, ptr::NonNull};

/// Record size is defined as `2^14 + 1`.
///
/// > ...the full encoded TLSInnerPlaintext MUST NOT exceed 2^14 + 1
/// > octets
/// - [source][0]
///
/// This value must also equal or exceed `<wolfssl/internal.h>`'s
/// `MAX_RECORD_SIZE` (though I'm not sure how to assert that yet).
///
/// [0]: https://www.rfc-editor.org/rfc/rfc8446#section-5.4
const TLS_MAX_RECORD_SIZE: usize = 2usize.pow(14) + 1;

/// Wraps [`wolfSSL_Init`][0]
///
/// This must be called internally by any binding which uses a library function.
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_init
fn wolf_init() -> Result<()> {
    static ONCE: std::sync::OnceLock<Result<()>> = std::sync::OnceLock::new();

    ONCE.get_or_init(|| {
        // SAFETY: [`wolfSSL_Init`][0] ([also][1]) must be called once
        // per application, this is enforced using the `ONCE:
        // OnceLock` and by ensuring that all entry points into this
        // crate call this method.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_init
        // [1]: https://www.wolfssl.com/doxygen/group__TLS.html#ga789ef74e34df659a62f06da2ea709737
        match unsafe { wolfssl_sys::wolfSSL_Init() } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(()),
            e => Err(Error::fatal(e)),
        }
    })
    .clone()
}

/// Wraps [`wolfSSL_Debugging_ON`][0] and [`wolfSSL_Debugging_OFF`][1]
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_on
/// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_off
#[cfg(feature = "debug")]
pub fn enable_debugging(on: bool) {
    wolf_init().expect("Unable to initialize wolfSSL");

    if on {
        // SAFETY: [`wolfSSL_Debugging_ON`][0] ([also][1]) requires `DEBUG_WOLFSSL` to be compiled in to succeed
        // This function will be compiled only on enabling feature `debug`
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_on
        // [1]: https://www.wolfssl.com/doxygen/group__Debug.html#ga192a2501d23697c2b56ce26b1af0eb2c
        match unsafe { wolfssl_sys::wolfSSL_Debugging_ON() } {
            0 => {}
            // This wrapper function is only enabled if we built wolfssl-sys with debugging on.
            wolfssl_sys::wolfCrypt_ErrorCodes_NOT_COMPILED_IN => {
                panic!("Inconsistent build, debug not enabled in wolfssl_sys")
            }
            e => unreachable!("wolfSSL_Debugging_ON: {e:?}"),
        }
    } else {
        // SAFETY: [`wolfSSL_Debugging_OFF`][0] ([also][1]) has no safety concerns as per documentation
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_off
        // [1]: https://www.wolfssl.com/doxygen/group__Debug.html#gafa8dab742182b891d80300fb195399ce
        unsafe { wolfssl_sys::wolfSSL_Debugging_OFF() }
    }
}

#[cfg(feature = "debug")]
pub use wolfssl_sys::wolfSSL_Logging_cb as WolfsslLoggingCallback;

/// Wraps [`wolfSSL_SetLoggingCb`][0]. You must call [`enable_debugging`] first to enable logging at runtime before setting the callback.
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Logging.html#function-wolfssl_setloggingcb
#[cfg(feature = "debug")]
pub fn set_logging_callback(cb: WolfsslLoggingCallback) {
    wolf_init().expect("Unable to initialize wolfSSL");

    // SAFETY: [`wolfSSL_SetLoggingCb`][0] would return an error if a function pointer is not provided, or we failed to set logging callback.
    // This function will be compiled only on enabling feature `debug`
    //
    // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Logging.html#function-wolfssl_setloggingcb
    match unsafe { wolfssl_sys::wolfSSL_SetLoggingCb(cb) } {
        0 => {}
        wolfssl_sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG => {
            panic!("Function pointer is not provided")
        }
        e => unreachable!("wolfSSL_SetLoggingCb: {e:?}"),
    }
}

/// TLS/DTLS protocol versions
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ProtocolVersion {
    /// SSL 2.0
    SslV2,
    /// SSL 3.0
    SslV3,
    /// TLS 1.0
    TlsV1_0,
    /// TLS 1.1
    TlsV1_1,
    /// TLS 1.2
    TlsV1_2,
    /// TLS 1.3
    TlsV1_3,
    /// DTLS 1.0
    DtlsV1_0,
    /// DTLS 1.2
    DtlsV1_2,
    /// DTLS 1.3
    DtlsV1_3,
    /// Unknown protocol version
    Unknown,
}

impl ProtocolVersion {
    /// Get a static string representation of the version.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtocolVersion::SslV2 => "ssl_2",
            ProtocolVersion::SslV3 => "ssl_3",
            ProtocolVersion::TlsV1_0 => "tls_1_0",
            ProtocolVersion::TlsV1_1 => "tls_1_1",
            ProtocolVersion::TlsV1_2 => "tls_1_2",
            ProtocolVersion::TlsV1_3 => "tls_1_3",
            ProtocolVersion::DtlsV1_0 => "dtls_1_0",
            ProtocolVersion::DtlsV1_2 => "dtls_1_2",
            ProtocolVersion::DtlsV1_3 => "dtls_1_3",
            ProtocolVersion::Unknown => "unknown",
        }
    }

    /// Checks if the protocol version is compatible with TLS 1.3
    fn is_tls_13(&self) -> bool {
        matches!(self, Self::TlsV1_3)
    }

    /// Checks if the protocol version is compatible with DTLS 1.3
    fn is_dtls_13(&self) -> bool {
        matches!(self, Self::DtlsV1_3)
    }
}

/// Corresponds to the various `wolf*_{client,server}_method()` APIs
#[derive(Debug, Copy, Clone)]
pub enum Method {
    /// `wolfDTLS_client_method`
    DtlsClient,
    /// `wolfDTLSv1_2_client_method`
    DtlsClientV1_2,
    /// `wolfDTLSv1_3_client_method`
    DtlsClientV1_3,
    /// `wolfDTLS_server_method`
    DtlsServer,
    /// `wolfDTLSv1_2_server_method`
    DtlsServerV1_2,
    /// `wolfDTLSv1_3_server_method`
    DtlsServerV1_3,
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

impl Method {
    /// Converts a [`Self`] into a [`wolfssl_sys::WOLFSSL_METHOD`]
    /// compatible with [`wolfssl_sys::wolfSSL_CTX_new`]
    fn into_method_ptr(self) -> Option<NonNull<wolfssl_sys::WOLFSSL_METHOD>> {
        let ptr = match self {
            // SAFETY: Per documentation [`wolfDTLS_client_method][0] and its sibling methods allocate memory for `WOLFSSL_METHOD` and initialize with proper values.
            // The documentation is unclear about when to free the memory.
            // Based on implementation[2], the api [`wolfSSL_CTX_new`][1] will consume this memory and thus take care of freeing it
            //
            // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfsslv3_client_method
            // [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_new
            // [2]: https://github.com/wolfSSL/wolfssl/blob/v5.6.3-stable/src/internal.c#L2156
            Self::DtlsClient => unsafe { wolfssl_sys::wolfDTLS_client_method() },
            // SAFETY: as above
            Self::DtlsClientV1_2 => unsafe { wolfssl_sys::wolfDTLSv1_2_client_method() },
            // SAFETY: as above
            Self::DtlsClientV1_3 => unsafe { wolfssl_sys::wolfDTLSv1_3_client_method() },
            // SAFETY: as above
            Self::DtlsServer => unsafe { wolfssl_sys::wolfDTLS_server_method() },
            // SAFETY: as above
            Self::DtlsServerV1_2 => unsafe { wolfssl_sys::wolfDTLSv1_2_server_method() },
            // SAFETY: as above
            Self::DtlsServerV1_3 => unsafe { wolfssl_sys::wolfDTLSv1_3_server_method() },
            // SAFETY: as above
            Self::TlsClient => unsafe { wolfssl_sys::wolfTLS_client_method() },
            // SAFETY: as above
            Self::TlsClientV1_2 => unsafe { wolfssl_sys::wolfTLSv1_2_client_method() },
            // SAFETY: as above
            Self::TlsClientV1_3 => unsafe { wolfssl_sys::wolfTLSv1_3_client_method() },
            // SAFETY: as above
            Self::TlsServer => unsafe { wolfssl_sys::wolfTLS_server_method() },
            // SAFETY: as above
            Self::TlsServerV1_2 => unsafe { wolfssl_sys::wolfTLSv1_2_server_method() },
            // SAFETY: as above
            Self::TlsServerV1_3 => unsafe { wolfssl_sys::wolfTLSv1_3_server_method() },
        };

        NonNull::new(ptr)
    }
}

/// Corresponds to the various defined `WOLFSSL_*` curves
#[derive(Debug, Copy, Clone)]
pub enum CurveGroup {
    /// `WOLFSSL_ECC_SECP256R1`
    EccSecp256R1,

    /// `WOLFSSL_ECC_X25519`
    EccX25519,

    /// `WOLFSSL_P256_KYBER_LEVEL1`
    #[cfg(feature = "postquantum")]
    P256KyberLevel1,
    /// `WOLFSSL_P384_KYBER_LEVEL3`
    #[cfg(feature = "postquantum")]
    P384KyberLevel3,
    /// `WOLFSSL_P521_KYBER_LEVEL5`
    #[cfg(feature = "postquantum")]
    P521KyberLevel5,

    /// `WOLFSSL_P256_ML_KEM_512`
    #[cfg(all(feature = "postquantum", not(feature = "kyber_only")))]
    P256MLKEM512,
    /// `WOLFSSL_P384_ML_KEM_768`
    #[cfg(all(feature = "postquantum", not(feature = "kyber_only")))]
    P384MLKEM768,
    /// `WOLFSSL_P521_ML_KEM_1024`
    #[cfg(all(feature = "postquantum", not(feature = "kyber_only")))]
    P521MLKEM1024,
}

impl CurveGroup {
    fn as_ffi(&self) -> std::os::raw::c_uint {
        use CurveGroup::*;
        match self {
            EccSecp256R1 => wolfssl_sys::WOLFSSL_ECC_SECP256R1,
            EccX25519 => wolfssl_sys::WOLFSSL_ECC_X25519,
            #[cfg(feature = "postquantum")]
            P256KyberLevel1 => wolfssl_sys::WOLFSSL_P256_KYBER_LEVEL1,
            #[cfg(feature = "postquantum")]
            P384KyberLevel3 => wolfssl_sys::WOLFSSL_P384_KYBER_LEVEL3,
            #[cfg(feature = "postquantum")]
            P521KyberLevel5 => wolfssl_sys::WOLFSSL_P521_KYBER_LEVEL5,
            #[cfg(all(feature = "postquantum", not(feature = "kyber_only")))]
            P256MLKEM512 => wolfssl_sys::WOLFSSL_P256_ML_KEM_512,
            #[cfg(all(feature = "postquantum", not(feature = "kyber_only")))]
            P384MLKEM768 => wolfssl_sys::WOLFSSL_P384_ML_KEM_768,
            #[cfg(all(feature = "postquantum", not(feature = "kyber_only")))]
            P521MLKEM1024 => wolfssl_sys::WOLFSSL_P521_ML_KEM_1024,
        }
    }
}

/// Defines a CA certificate
#[derive(Debug, Copy, Clone)]
pub enum RootCertificate<'a> {
    /// In-memory PEM buffer
    PemBuffer(&'a [u8]),
    /// In-memory ASN1 buffer
    Asn1Buffer(&'a [u8]),
    /// Path to a PEM file, or a directory of PEM files
    PemFileOrDirectory(&'a std::path::Path),
}

/// Defines either a public or private key
#[derive(Debug, Copy, Clone)]
pub enum Secret<'a> {
    /// In-memory ASN1 buffer
    Asn1Buffer(&'a [u8]),
    /// Path to ASN1 file
    Asn1File(&'a std::path::Path),
    /// In-memory PEM buffer
    PemBuffer(&'a [u8]),
    /// Path to PEM file
    PemFile(&'a std::path::Path),
}

/// SSL Verification method
/// Ref: `https://www.wolfssl.com/doxygen/group__Setup.html#gaf9198658e31dd291088be18262ef2354`
#[derive(Debug, Copy, Clone)]
pub enum SslVerifyMode {
    /// No verification done
    SslVerifyNone,
    /// Verify peers certificate
    SslVerifyPeer,
    /// Verify client's certificate (applicable only for server)
    SslVerifyFailIfNoPeerCert,
    /// Verify client's certificate except PSK connection (applicable only for server)
    SslVerifyFailExceptPsk,
}

impl Default for SslVerifyMode {
    fn default() -> Self {
        Self::SslVerifyPeer
    }
}

impl From<SslVerifyMode> for c_int {
    fn from(value: SslVerifyMode) -> Self {
        match value {
            SslVerifyMode::SslVerifyNone => WOLFSSL_VERIFY_NONE,
            SslVerifyMode::SslVerifyPeer => WOLFSSL_VERIFY_PEER,
            SslVerifyMode::SslVerifyFailIfNoPeerCert => WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            SslVerifyMode::SslVerifyFailExceptPsk => WOLFSSL_VERIFY_FAIL_EXCEPT_PSK,
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

    #[test_case(ProtocolVersion::SslV2 => "ssl_2")]
    #[test_case(ProtocolVersion::SslV3 => "ssl_3")]
    #[test_case(ProtocolVersion::TlsV1_0 => "tls_1_0")]
    #[test_case(ProtocolVersion::TlsV1_1 => "tls_1_1")]
    #[test_case(ProtocolVersion::TlsV1_2 => "tls_1_2")]
    #[test_case(ProtocolVersion::TlsV1_3 => "tls_1_3")]
    #[test_case(ProtocolVersion::DtlsV1_0 => "dtls_1_0")]
    #[test_case(ProtocolVersion::DtlsV1_2 => "dtls_1_2")]
    #[test_case(ProtocolVersion::DtlsV1_3 => "dtls_1_3")]
    #[test_case(ProtocolVersion::Unknown => "unknown")]
    fn protocol_version_as_str(p: ProtocolVersion) -> &'static str {
        p.as_str()
    }

    #[test_case(SslVerifyMode::SslVerifyNone => WOLFSSL_VERIFY_NONE)]
    #[test_case(SslVerifyMode::SslVerifyPeer => WOLFSSL_VERIFY_PEER)]
    #[test_case(SslVerifyMode::SslVerifyFailIfNoPeerCert => WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT)]
    #[test_case(SslVerifyMode::SslVerifyFailExceptPsk => WOLFSSL_VERIFY_FAIL_EXCEPT_PSK)]
    fn ssl_verify_mode(s: SslVerifyMode) -> c_int {
        s.into()
    }
}
