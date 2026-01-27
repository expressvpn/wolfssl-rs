mod bindings;
pub use bindings::*;

/// Get WolfSSL version tag via `git describe`.
pub fn get_wolfssl_version_tag() -> &'static str {
    env!("VERGEN_GIT_DESCRIBE")
}

/**
 * Add more tests to gain more confidence in the bindings
 */
#[cfg(test)]
mod tests {
    use std::os::raw::c_int;

    use test_case::test_case;
    #[cfg(unix)]
    type CurveGroupType = std::os::raw::c_uint;
    #[cfg(windows)]
    type CurveGroupType = std::os::raw::c_int;

    use super::*;
    #[test]
    fn init_wolfssl() {
        unsafe {
            let res = wolfSSL_Init();
            assert_eq!(res, WOLFSSL_SUCCESS as c_int);
        }
    }

    #[cfg(feature = "postquantum")]
    #[test_case(WOLFSSL_P521_KYBER_LEVEL5)]
    #[cfg_attr(not(feature = "kyber_only"), test_case(WOLFSSL_SECP521R1MLKEM1024))]
    fn test_post_quantum_available(group: CurveGroupType) {
        unsafe {
            // Init WolfSSL
            let res = wolfSSL_Init();
            assert_eq!(res, WOLFSSL_SUCCESS as c_int);

            // Set up client method
            let method = wolfTLSv1_3_client_method();

            // Create context
            let context = wolfSSL_CTX_new(method);

            // Create new SSL stream
            let ssl = wolfSSL_new(context);

            let res = wolfSSL_UseKeyShare(ssl, group.try_into().unwrap());

            // Check that Kyber/ML-KEM was enabled
            assert_eq!(res, WOLFSSL_SUCCESS as c_int);
        }
    }

    #[test]
    fn test_wolfssl_version_tag_clean() {
        // Make sure the working tree is clean
        assert!(!get_wolfssl_version_tag().contains("dirty"))
    }
}
