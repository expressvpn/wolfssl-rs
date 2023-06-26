mod data_buffer;

use crate::{
    context::WolfContext,
    error::{Result, WolfError},
    TLS_MAX_RECORD_SIZE,
};
pub use data_buffer::DataBuffer;

use bytes::Bytes;
use parking_lot::Mutex;

use std::ptr::NonNull;

#[allow(missing_docs)]
pub struct WolfSession {
    ssl: Mutex<NonNull<wolfssl_sys::WOLFSSL>>,

    // A `Box` because we need a stable pointer address
    callback_read_buffer: Box<DataBuffer>,
    callback_write_buffer: Box<DataBuffer>,
}

impl WolfSession {
    /// Invokes [`wolfSSL_new`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_new
    pub fn new_from_context(ctx: &WolfContext) -> Option<Self> {
        let ptr = unsafe { wolfssl_sys::wolfSSL_new(ctx.ctx().as_ptr()) };

        let mut session = Self {
            ssl: Mutex::new(NonNull::new(ptr)?),
            callback_read_buffer: Box::new(DataBuffer::with_capacity(TLS_MAX_RECORD_SIZE)),
            callback_write_buffer: Box::new(DataBuffer::with_capacity(TLS_MAX_RECORD_SIZE)),
        };

        session.register_io_context();

        Some(session)
    }

    /// Gets the current cipher of the session.
    /// If the cipher name is "None", return None.
    pub fn get_current_cipher_name(&self) -> Option<String> {
        let cipher = unsafe { wolfssl_sys::wolfSSL_get_current_cipher(self.ssl.lock().as_ptr()) };
        let cipher = if !cipher.is_null() {
            let name = unsafe {
                let name = wolfssl_sys::wolfSSL_CIPHER_get_name(cipher);
                std::ffi::CStr::from_ptr(name).to_str().ok()?.to_string()
            };
            Some(name)
        } else {
            None
        };

        match cipher {
            Some(x) if x == "None" => None,
            x => x,
        }
    }

    /// Invokes [`wolfSSL_is_init_finished`][0]
    ///
    /// "Init" in this case is the formation of the TLS connection.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_is_init_finished
    pub fn is_init_finished(&self) -> bool {
        match unsafe { wolfssl_sys::wolfSSL_is_init_finished(self.ssl.lock().as_ptr()) } {
            0 => false,
            1 => true,
            _ => unimplemented!("Only 0 or 1 is expected as return value"),
        }
    }

    /// Invokes [`wolfSSL_negotiate`][0] *once*.
    ///
    /// The distinction is important because it takes more than one invocation
    /// to successfully form a secure session.
    ///
    /// This method will trigger WolfSSL's IO callbacks, so the caller is
    /// responsible for:
    /// - Sending the resulting data that is generated (collected via
    ///   [`Self::io_write_out`]) to the destination.
    /// - Making the response data from the destination visible to this session
    ///   via [`Self::io_read_in`].
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_negotiate
    pub fn try_negotiate(&self) -> Result<()> {
        let ret = unsafe {
            let ssl = self.ssl.lock();
            wolfssl_sys::wolfSSL_negotiate(ssl.as_ptr())
        };

        self.check_error(ret)
    }

    /// Extracts data wolfSSL wants sent over the network, if there is any.
    pub fn io_write_out(&mut self) -> Bytes {
        self.callback_write_buffer.split().freeze()
    }

    /// Makes external data visible to the WolfSSL Custom IO read callback the
    /// next time it is called.
    pub fn io_read_in(&mut self, b: Bytes) {
        self.callback_read_buffer.extend_from_slice(&b)
    }
}

impl WolfSession {
    /// Registers a context that will be visible within the custom IO callbacks
    /// tied to this `WOLFSSL` session.
    ///
    /// This is done via [`wolfSSL_SetIOReadCtx`][0] and
    /// [`wolfSSL_SetIOWriteCtx`][1].
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setioreadctx
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setiowritectx
    fn register_io_context(&mut self) {
        let ssl = self.ssl.lock();
        let read_buf = self.callback_read_buffer.as_mut() as *mut _ as *mut std::ffi::c_void;
        let write_buf = self.callback_write_buffer.as_mut() as *mut _ as *mut std::ffi::c_void;
        unsafe {
            wolfssl_sys::wolfSSL_SetIOReadCtx(ssl.as_ptr(), read_buf);
            wolfssl_sys::wolfSSL_SetIOWriteCtx(ssl.as_ptr(), write_buf);
        }
    }

    /// Generates a [`WolfError`] if one exists.
    ///
    /// This is stateful, and collects the error of the previous invoked method.
    fn check_error(&self, ret: std::ffi::c_int) -> Result<()> {
        let ssl = self.ssl.lock();
        let result = unsafe { wolfssl_sys::wolfSSL_get_error(ssl.as_ptr(), ret) };
        WolfError::check(result)
    }
}

#[cfg(test)]
impl WolfSession {
    pub fn read_buffer(&self) -> &DataBuffer {
        self.callback_read_buffer.as_ref()
    }

    pub fn write_buffer(&self) -> &DataBuffer {
        self.callback_write_buffer.as_ref()
    }
}

impl Drop for WolfSession {
    /// Invokes [`wolfSSL_free`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_free
    fn drop(&mut self) {
        unsafe { wolfssl_sys::wolfSSL_free(self.ssl.lock().as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use crate::{context::WolfContextBuilder, RootCertificate, Secret, WolfMethod};

    use std::sync::OnceLock;

    const CA_CERT: &[u8] = &include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/ca_cert_der_2048"
    ));

    const SERVER_CERT: &[u8] = &include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/server_cert_der_2048"
    ));

    const SERVER_KEY: &[u8] = &include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/server_key_der_2048"
    ));

    static INIT_ENV_LOGGER: OnceLock<()> = OnceLock::new();

    #[test]
    fn try_negotiate() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let client_ctx = WolfContextBuilder::new(WolfMethod::TlsClientV1_3)
            .expect("client WolfBuilder")
            .with_root_certificate(RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap()
            .build();

        let server_ctx = WolfContextBuilder::new(WolfMethod::TlsServerV1_3)
            .expect("new(crate::WolfMethod::TlsServer)")
            .with_certificate(Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(Secret::Asn1Buffer(SERVER_KEY))
            .expect("server WolfBuilder")
            .build();

        let mut client_ssl = client_ctx.new_session().unwrap();
        let mut server_ssl = server_ctx.new_session().unwrap();

        for _ in 0..4 {
            client_ssl
                .try_negotiate()
                // WANT_READ/WRITE are nonfatal errors
                .or_else(|x| if x.is_non_fatal() { Ok(()) } else { Err(x) })
                .unwrap();

            server_ssl
                .try_negotiate()
                // WANT_READ/WRITE are nonfatal errors
                .or_else(|x| if x.is_non_fatal() { Ok(()) } else { Err(x) })
                .unwrap();

            client_ssl.io_read_in(server_ssl.io_write_out());
            server_ssl.io_read_in(client_ssl.io_write_out());
        }

        // The handshake should complete in 4 rounds.
        assert!(client_ssl.is_init_finished());
        assert!(server_ssl.is_init_finished());
    }
}
