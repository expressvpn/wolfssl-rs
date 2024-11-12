mod bindings;
pub use bindings::*;

/**
 * Add more tests to gain more confidence in the bindings
 */
#[cfg(test)]
mod tests {
    use std::os::raw::c_int;

    use super::*;
    #[test]
    fn init_wolfssl() {
        unsafe {
            let res = wolfSSL_Init();
            assert_eq!(res, WOLFSSL_SUCCESS as c_int);
        }
    }

    #[test]
    #[cfg(feature = "postquantum")]
    fn test_post_quantum_available() {
        // Test if original Kyber is availble
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

            // Enable Kyber
            let res = wolfSSL_UseKeyShare(ssl, WOLFSSL_P521_KYBER_LEVEL5.try_into().unwrap());

            // Check that ML-KEM was enabled
            assert_eq!(res, WOLFSSL_SUCCESS as c_int);
        }

        // Test ML-KEM is available
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

            // Enable ML-KEM
            let res = wolfSSL_UseKeyShare(ssl, WOLFSSL_P521_ML_KEM_1024.try_into().unwrap());

            // Check that ML-KEM was enabled
            assert_eq!(res, WOLFSSL_SUCCESS as c_int);
        }
    }
}
