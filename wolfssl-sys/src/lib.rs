mod bindings;
pub use bindings::*;

/**
 * Add more tests to gain more confidence in the bindings
 */
#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn init_wolfssl() {
        unsafe {
            let res = wolfSSL_Init();
            assert_eq!(res, WOLFSSL_SUCCESS);
        }
    }

    #[test]
    #[cfg(feature = "postquantum")]
    fn test_post_quantum_available() {
        unsafe {
            // Init WolfSSL
            let res = wolfSSL_Init();
            assert_eq!(res, WOLFSSL_SUCCESS);

            // Set up client method
            let method = wolfTLSv1_3_client_method();

            // Create context
            let context = wolfSSL_CTX_new(method);

            // Create new SSL stream
            let ssl = wolfSSL_new(context);

            // Enable Kyber
            let res = wolfSSL_UseKeyShare(ssl, WOLFSSL_P521_KYBER_LEVEL5.try_into().unwrap());

            // Check that Kyber was enabled
            assert_eq!(res, WOLFSSL_SUCCESS);
        }
    }
}
