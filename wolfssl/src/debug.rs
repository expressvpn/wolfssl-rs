#![cfg(feature = "debug")]

/// Wraps [`wolfSSL_Debugging_ON`][0] and [`wolfSSL_Debugging_OFF`][1]
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_on
/// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_off
pub fn enable_debugging(on: bool) {
    crate::wolf_init().expect("Unable to initialize wolfSSL");

    if on {
        // SAFETY: [`wolfSSL_Debugging_ON`][0] ([also][1]) requires `DEBUG_WOLFSSL` to be compiled in to succeed
        // This function will be compiled only on enabling feature `debug`
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_on
        // [1]: https://www.wolfssl.com/doxygen/group__Debug.html#ga192a2501d23697c2b56ce26b1af0eb2c
        match unsafe { wolfssl_sys::wolfSSL_Debugging_ON() } {
            0 => {}
            // This wrapper function is only enabled if we built wolfssl-sys with debugging on.
            wolfssl_sys::NOT_COMPILED_IN => {
                panic!("Inconsistent build, debug not enabled in wolfssl_sys")
            }
            e => unreachable!("{e:?}"),
        }
    } else {
        // SAFETY: [`wolfSSL_Debugging_OFF`][0] ([also][1]) has no safety concerns as per documentation
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function-wolfssl_debugging_off
        // [1]: https://www.wolfssl.com/doxygen/group__Debug.html#gafa8dab742182b891d80300fb195399ce
        unsafe { wolfssl_sys::wolfSSL_Debugging_OFF() }
    }
}
