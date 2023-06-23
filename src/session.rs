use crate::context::WolfContext;

#[allow(missing_docs)]
pub struct WolfSession(*mut wolfssl_sys::WOLFSSL);

impl WolfSession {
    /// Invokes [`wolfSSL_new`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_new
    pub fn new_from_context(ctx: &WolfContext) -> Option<Self> {
        let ptr = unsafe { wolfssl_sys::wolfSSL_new(ctx.ctx().as_ptr()) };
        if !ptr.is_null() {
            Some(WolfSession(ptr))
        } else {
            None
        }
    }

    /// Gets the current cipher of the session.
    /// If there is no cipher, returns `Some("NONE")`.
    pub fn get_current_cipher_name(&self) -> Option<String> {
        let cipher = unsafe { wolfssl_sys::wolfSSL_get_current_cipher(self.0) };
        if !cipher.is_null() {
            let name = unsafe {
                let name = wolfssl_sys::wolfSSL_CIPHER_get_name(cipher);
                std::ffi::CStr::from_ptr(name).to_str().ok()?.to_string()
            };
            Some(name)
        } else {
            None
        }
    }

    /// Invokes [`wolfSSL_is_init_finished`][0]
    ///
    /// "Init" in this case is the formation of the TLS connection.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_is_init_finished
    pub fn is_init_finished(&self) -> bool {
        match unsafe { wolfssl_sys::wolfSSL_is_init_finished(self.0) } {
            0 => false,
            1 => true,
            _ => unimplemented!("Only 0 or 1 is expected as return value"),
        }
    }
}

impl Drop for WolfSession {
    /// Invokes [`wolfSSL_free`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_free
    fn drop(&mut self) {
        unsafe { wolfssl_sys::wolfSSL_free(self.0) }
    }
}
