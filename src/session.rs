use crate::{async_client::WolfClientCallbackContext, errors::WolfError, WolfContext};
use parking_lot::Mutex;
use tokio::io::ReadBuf;

#[allow(missing_docs)]
pub struct WolfSession {
    pub(crate) _ctx: WolfContext,
    pub(crate) ssl: Mutex<*mut wolfssl_sys::WOLFSSL>,
}

impl Drop for WolfSession {
    /// Invokes [`wolfSSL_free`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_free
    fn drop(&mut self) {
        let ssl = self.ssl.lock();
        unsafe { wolfssl_sys::wolfSSL_free(*ssl) }
    }
}

impl WolfSession {
    /// Gets the current cipher of the session. If there is no cipher,
    /// returns `Some("NONE")`.
    pub fn get_current_cipher_name(&self) -> Option<String> {
        let ssl = self.ssl.lock();
        let cipher = unsafe { wolfssl_sys::wolfSSL_get_current_cipher(*ssl) };
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
        let ssl = self.ssl.lock();
        match unsafe { wolfssl_sys::wolfSSL_is_init_finished(*ssl) } {
            0 => false,
            1 => true,
            _ => unimplemented!("Only 0 or 1 is expected as return value"),
        }
    }

    /// Wraps [`wolfSSL_accept`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_accept
    pub(crate) fn try_accept(&self) -> Result<(), WolfError> {
        let ssl = self.ssl.lock();
        if unsafe { wolfssl_sys::wolfSSL_accept(*ssl) } == wolfssl_sys::WOLFSSL_FATAL_ERROR {
            Err(WolfError::get_error(*ssl, wolfssl_sys::WOLFSSL_FATAL_ERROR))
        } else {
            Ok(())
        }
    }

    /// Wraps [`wolfSSL_connect`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_connect
    pub(crate) fn try_connect(&self) -> Result<(), WolfError> {
        let ssl = self.ssl.lock();
        if unsafe { wolfssl_sys::wolfSSL_connect(*ssl) } == wolfssl_sys::WOLFSSL_FATAL_ERROR {
            Err(WolfError::get_error(*ssl, wolfssl_sys::WOLFSSL_FATAL_ERROR))
        } else {
            Ok(())
        }
    }

    /// Wraps [`wolfSSL_negotiate`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_negotiate
    pub(crate) fn try_negotiate(&self) -> Result<(), WolfError> {
        let ssl = self.ssl.lock();
        if unsafe { wolfssl_sys::wolfSSL_negotiate(*ssl) } == wolfssl_sys::WOLFSSL_FATAL_ERROR {
            Err(WolfError::get_error(*ssl, wolfssl_sys::WOLFSSL_FATAL_ERROR))
        } else {
            Ok(())
        }
    }

    /// Registers a [`WolfClientCallbackContext`] to this `WOLFSSL`
    /// session.
    ///
    /// This is done via [`wolfSSL_SetIOReadCtx`][0] and
    /// [`wolfSSL_SetIOWriteCtx`][1].
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setioreadctx
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setiowritectx
    ///
    // TODO (pangt): It's not clear how safe this is. Should it at
    // least be `Pin`?
    pub(crate) fn set_io_context(&self, ctx: &mut WolfClientCallbackContext) {
        let ssl_session_ptr = self.ssl.lock();
        let session_context_ptr = ctx as *mut _ as *mut ::std::os::raw::c_void;
        unsafe {
            wolfssl_sys::wolfSSL_SetIOReadCtx(*ssl_session_ptr, session_context_ptr);
            wolfssl_sys::wolfSSL_SetIOWriteCtx(*ssl_session_ptr, session_context_ptr);
        }
    }

    /// Invokes [`wolfSSL_read`][0] and fills `buf` with the results
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_read
    pub(crate) fn read_into(&self, buf: &mut ReadBuf) -> Result<usize, WolfError> {
        let ssl = self.ssl.lock();
        match unsafe {
            wolfssl_sys::wolfSSL_read(
                *ssl,
                &mut buf.initialize_unfilled()[..] as *mut _ as *mut ::std::os::raw::c_void,
                buf.remaining() as i32,
            )
        } {
            x if x > 0 => {
                buf.advance(x as usize);
                Ok(x as usize)
            }
            x if x <= 0 => Err(WolfError::get_error(*ssl, x)),
            x => {
                unreachable!("Unhandled wolfSSL_read return value {x}");
            }
        }
    }

    /// Invokes [`wolfSSL_write`][0] and write the value of `buf`.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_write
    pub(crate) fn write(&self, buf: &[u8]) -> Result<usize, WolfError> {
        let ssl = self.ssl.lock();
        match unsafe {
            let buf_ptr = buf as *const _ as *const ::std::os::raw::c_void;
            wolfssl_sys::wolfSSL_write(*ssl, buf_ptr, buf.len() as i32)
        } {
            x if x <= 0 => Err(WolfError::get_error(*ssl, x)),
            x if x > 0 => Ok(x as usize),
            x => {
                unreachable!("Unhandled wolfSSL_write return value {x}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        test_helpers::{make_connected_clients, INIT_ENV_LOGGER},
        WolfContextBuilder, WolfMethod,
    };

    #[tokio::test]
    async fn session_get_current_cipher_name() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        crate::wolf_init().unwrap();

        let client_builder = WolfContextBuilder::new(WolfMethod::TlsClient)
            .and_then(|b| b.with_secure_renegotiation())
            .unwrap();
        let server_builder = WolfContextBuilder::new(WolfMethod::TlsServer)
            .and_then(|b| b.with_secure_renegotiation())
            .unwrap();

        let (client, _server) = make_connected_clients(client_builder, server_builder).await;

        assert!(client.ssl_session.get_current_cipher_name().is_some());
    }
}
