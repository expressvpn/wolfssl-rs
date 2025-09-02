mod bindings;
pub use bindings::*;

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
    #[cfg_attr(not(feature = "kyber_only"), test_case(WOLFSSL_P521_ML_KEM_1024))]
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
}
