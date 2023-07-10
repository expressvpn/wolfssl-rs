mod data_buffer;

use crate::{
    context::WolfContext,
    error::{Error, Poll, PollResult, Result},
    WolfMethod, TLS_MAX_RECORD_SIZE,
};
pub use data_buffer::DataBuffer;

use bytes::{Buf, Bytes, BytesMut};
use parking_lot::Mutex;

use std::{
    ffi::{c_int, c_void},
    ptr::NonNull,
    unreachable,
};

#[allow(missing_docs)]
pub struct WolfSession {
    method: WolfMethod,

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
            method: ctx.method(),
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
    pub fn try_negotiate(&mut self) -> PollResult<()> {
        match unsafe {
            let ssl = self.ssl.lock();
            wolfssl_sys::wolfSSL_negotiate(ssl.as_ptr())
        } {
            wolfssl_sys::WOLFSSL_SUCCESS => Ok(Poll::Ready(())),
            x @ wolfssl_sys::WOLFSSL_FATAL_ERROR => match self.get_error(x) {
                wolfssl_sys::WOLFSSL_ERROR_WANT_READ | wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE => {
                    Ok(Poll::Pending)
                }
                wolfssl_sys::wolfSSL_ErrorCodes_APP_DATA_READY
                    if self.is_secure_renegotiation_supported() =>
                {
                    self.handle_app_data().map(Poll::AppData)
                }
                e => Err(Error::fatal(e)),
            },
            _ => unreachable!(),
        }
    }

    /// Invokes [`wolfSSL_shutdown`][0] *once*.
    ///
    /// Like other IO-related functions in wolfSSL, this would require the
    /// caller to ensure that the necessary data exchange over the network is
    /// accomplished (see [`Self::try_negotiate`] for more details).
    ///
    /// Fortunately, if there is no intent to reuse the connection, you do not
    /// need to await for a response from the other side.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_shutdown
    pub fn try_shutdown(&mut self) -> PollResult<()> {
        match unsafe {
            let ssl = self.ssl.lock();
            wolfssl_sys::wolfSSL_shutdown(ssl.as_ptr())
        } {
            wolfssl_sys::WOLFSSL_SUCCESS => Ok(Poll::Ready(())),
            wolfssl_sys::WOLFSSL_SHUTDOWN_NOT_DONE => Ok(Poll::Pending),
            x @ wolfssl_sys::WOLFSSL_FATAL_ERROR => match self.get_error(x) {
                wolfssl_sys::WOLFSSL_ERROR_WANT_READ | wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE => {
                    Ok(Poll::Pending)
                }
                wolfssl_sys::wolfSSL_ErrorCodes_APP_DATA_READY
                    if self.is_secure_renegotiation_supported() =>
                {
                    self.handle_app_data().map(Poll::AppData)
                }
                x => Err(Error::fatal(x)),
            },
            _ => unreachable!(),
        }
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

    /// Invokes [`wolfSSL_write`][0] *once*.
    ///
    /// Given a buffer, consumes as much of it as possible, writing into the
    /// network.
    ///
    /// This method will return the number of bytes that was successfully
    /// written into wolfSSL.
    ///
    /// It is not guaranteed that the entire buffer will be consumed, since we
    /// only invoke `wolfSSL_write` once.
    ///
    /// This functionally means that the next invocation of
    /// [`Self::io_write_out`] will return a non-empty buffer. The caller must
    /// then manually handle the data transfer.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_write
    //
    // Note that even if no data was consumed, WolfSSL might take this
    // opportunity to update its internal state (for example, if it needs to
    // update encryption keys). This can be seen in
    // [`Self::trigger_update_keys`].
    pub fn try_write(&mut self, data_in: &mut BytesMut) -> PollResult<usize> {
        match unsafe {
            let ssl = self.ssl.lock();
            wolfssl_sys::wolfSSL_write(
                ssl.as_ptr(),
                data_in.as_ptr() as *const c_void,
                data_in.len() as c_int,
            )
        } {
            x if x > 0 => {
                data_in.advance(x as usize);
                Ok(Poll::Ready(x as usize))
            }
            x @ (0 | wolfssl_sys::WOLFSSL_FATAL_ERROR) => match self.get_error(x) {
                wolfssl_sys::WOLFSSL_ERROR_NONE => Ok(Poll::Ready(0)),
                wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE | wolfssl_sys::WOLFSSL_ERROR_WANT_READ => {
                    Ok(Poll::Pending)
                }
                wolfssl_sys::wolfSSL_ErrorCodes_APP_DATA_READY
                    if self.is_secure_renegotiation_supported() =>
                {
                    self.handle_app_data().map(Poll::AppData)
                }
                e => Err(Error::fatal(e)),
            },
            e => Err(Error::fatal(e)),
        }
    }

    /// Invokes [`wolfSSL_read`][0] *once*.
    ///
    /// This can be thought of as the inverse to [`Self::try_write`]:
    /// - It reads data from WolfSSL into a buffer.
    /// - To progress, it requires data to be fed in via [`Self::io_read_in`].
    /// - It appends data to the given buffer, up to its given capacity.
    ///   - It does not alter existing data inside the buffer.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_read
    //
    // Like [`Self::try_write`], we call through to `wolfSSL_read` even if there
    // is no space to allow WolfSSL's internal state to advance.
    pub fn try_read(&mut self, data_out: &mut BytesMut) -> PollResult<usize> {
        let buf = data_out.spare_capacity_mut();

        match unsafe {
            let ssl = self.ssl.lock();
            wolfssl_sys::wolfSSL_read(
                ssl.as_ptr(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as c_int,
            )
        } {
            x if x > 0 => {
                // Now that we've initialized this memory segment, update the
                // length to account for the initialized bits
                unsafe {
                    data_out.set_len(data_out.len() + x as usize);
                }
                Ok(Poll::Ready(x as usize))
            }
            x @ (0 | wolfssl_sys::WOLFSSL_FATAL_ERROR) => match self.get_error(x) {
                wolfssl_sys::WOLFSSL_ERROR_WANT_READ | wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE => {
                    Ok(Poll::Pending)
                }
                wolfssl_sys::WOLFSSL_ERROR_NONE => Ok(Poll::Ready(0)),
                wolfssl_sys::wolfSSL_ErrorCodes_APP_DATA_READY
                    if self.is_secure_renegotiation_supported() =>
                {
                    self.handle_app_data().map(Poll::AppData)
                }
                e => Err(Error::fatal(e)),
            },
            e => Err(Error::fatal(e)),
        }
    }

    /// Checks if this session supports secure renegotiation
    ///
    /// Only some D/TLS connections support secure renegotiation, so this method
    /// checks if it's something we can do here.
    pub fn is_secure_renegotiation_supported(&self) -> bool {
        match unsafe {
            let ssl = self.ssl.lock();
            wolfssl_sys::wolfSSL_SSL_get_secure_renegotiation_support(ssl.as_ptr())
        } {
            0 => false,
            1 => true,
            _ => unreachable!(),
        }
    }

    /// Checks if there is an ongoing secure renegotiation triggered by
    /// [`Self::try_rehandshake`].
    //
    // NOTE (pangt): I can't find online documentation on
    // `wolfSSL_SSL_renegotiate_pending`, so no links to it.
    pub fn is_secure_renegotiation_pending(&self) -> bool {
        match unsafe {
            let ssl = self.ssl.lock();
            wolfssl_sys::wolfSSL_SSL_renegotiate_pending(ssl.as_ptr())
        } {
            0 => false,
            1 => true,
            _ => unreachable!(),
        }
    }

    /// Invokes [`wolfSSL_Rehandshake`][0] *once*.
    ///
    /// Is a no-op unless the session supports secure renegotiation.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html?query=wolfssl_rehandshake#function-wolfssl_rehandshake
    pub fn try_rehandshake(&mut self) -> PollResult<()> {
        if !self.is_secure_renegotiation_supported() {
            return Ok(Poll::Ready(()));
        }

        match unsafe {
            let ssl = self.ssl.lock();
            wolfssl_sys::wolfSSL_Rehandshake(ssl.as_ptr())
        } {
            wolfssl_sys::WOLFSSL_SUCCESS => Ok(Poll::Ready(())),
            x @ wolfssl_sys::WOLFSSL_FATAL_ERROR => match self.get_error(x) {
                wolfssl_sys::WOLFSSL_ERROR_WANT_READ | wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE => {
                    Ok(Poll::Pending)
                }
                wolfssl_sys::wolfSSL_ErrorCodes_APP_DATA_READY
                    if self.is_secure_renegotiation_supported() =>
                {
                    self.handle_app_data().map(Poll::AppData)
                }
                e => Err(Error::fatal(e)),
            },
            _ => unreachable!(),
        }
    }

    /// Checks if the session is over TLS 1.3
    pub fn is_tls_13(&self) -> bool {
        self.method.is_tls_13()
    }

    /// Invokes [`wolfSSL_update_keys`][0] *once*
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_update_keys
    pub fn try_trigger_update_key(&mut self) -> PollResult<()> {
        if !self.method.is_tls_13() {
            return Ok(Poll::Ready(()));
        }

        match unsafe {
            let ssl = self.ssl.lock();
            wolfssl_sys::wolfSSL_update_keys(ssl.as_ptr())
        } {
            wolfssl_sys::WOLFSSL_SUCCESS => Ok(Poll::Ready(())),
            wolfssl_sys::BAD_FUNC_ARG => unreachable!(),
            wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE => Ok(Poll::Pending),
            e => unreachable!("Received unknown code {e}"),
        }
    }

    /// Invokes [`wolfSSL_key_update_response`][0]
    ///
    /// Returns `true` if the client has sent a key update and is expecting a
    /// response, `false` otherwise.
    ///
    /// Note that this is a TLS 1.3 only feature. If the session is not TLS 1.3
    /// we will always return false.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_key_update_response
    pub fn is_update_keys_pending(&self) -> bool {
        if !self.method.is_tls_13() {
            return false;
        }

        let mut required = std::mem::MaybeUninit::<c_int>::uninit();

        match unsafe {
            let ssl = self.ssl.lock();
            wolfssl_sys::wolfSSL_key_update_response(ssl.as_ptr(), required.as_mut_ptr())
        } {
            0 => {}
            // panic on non-success, because `ssl` is always non-null and the
            // method here must be TLS1.3
            _ => unreachable!(),
        }

        match unsafe { required.assume_init() } {
            1 => true,
            0 => false,
            _ => unreachable!(),
        }
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

    /// Extracts a given error code from this session, by invoking
    /// [`wolfSSL_get_error`][0].
    ///
    /// This is stateful, and collects the error of the previous invoked method.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function_wolfssl_get_error
    fn get_error(&self, ret: c_int) -> c_int {
        let ssl = self.ssl.lock();
        unsafe { wolfssl_sys::wolfSSL_get_error(ssl.as_ptr(), ret) }
    }

    /// During secure renegotiation, wolfssl allows the user to send and receive data.
    ///
    /// If data is detected, WolfSSL will return a `APP_DATA_READY` code, it is then
    /// expected that we immediately read this data, or risk it dropping.
    ///
    /// Since every WolfSSL TLS API could raise this error, the logic is
    /// centralized here, in this helper function.
    //
    // It's implied that the data has already arrived and `wolfSSL_read` will
    // not return a `WANT_READ` or similar error code, so if we see them we will
    // convert it to an error.
    fn handle_app_data(&mut self) -> Result<Bytes> {
        debug_assert!(self.is_secure_renegotiation_supported());

        let mut buf = BytesMut::with_capacity(TLS_MAX_RECORD_SIZE);
        // Collect the appdata wolfssl kindly informed us about.
        match self.try_read(&mut buf) {
            Ok(Poll::Ready(_)) => Ok(buf.freeze()),
            Err(Error::Fatal(e) | Error::AppData(e)) => Err(Error::AppData(e)),
            Ok(Poll::Pending) => {
                unreachable!("App data is ready, so why are we waiting?")
            }
            // Lightway Core (C) does recurse, but only seems to
            // care about the last wolfssl_read, which likely
            // means that this won't recurse.
            Ok(Poll::AppData(_)) => {
                unreachable!("We assume that no nested calls are possible.")
            }
        }
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
    use super::*;
    use crate::{
        context::WolfContextBuilder, RootCertificate, Secret, WolfContext, WolfMethod, WolfSession,
        TLS_MAX_RECORD_SIZE,
    };

    use std::sync::OnceLock;

    use test_case::test_case;

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

    struct TestClient {
        _ctx: WolfContext,
        ssl: WolfSession,
    }

    fn make_connected_clients() -> (TestClient, TestClient) {
        make_connected_clients_with_method(WolfMethod::TlsClientV1_3, WolfMethod::TlsServerV1_3)
    }

    fn make_connected_clients_with_method(
        client_method: WolfMethod,
        server_method: WolfMethod,
    ) -> (TestClient, TestClient) {
        let client_ctx = WolfContextBuilder::new(client_method)
            .unwrap_or_else(|| panic!("new(WolfMethod::{client_method:?})"))
            .with_root_certificate(RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap()
            .with_secure_renegotiation()
            .unwrap()
            .build();

        let server_ctx = WolfContextBuilder::new(server_method)
            .unwrap_or_else(|| panic!("new(WolfMethod::{server_method:?})"))
            .with_certificate(Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(Secret::Asn1Buffer(SERVER_KEY))
            .expect("server WolfBuilder")
            .with_secure_renegotiation()
            .unwrap()
            .build();

        let client_ssl = client_ctx.new_session().unwrap();
        let server_ssl = server_ctx.new_session().unwrap();

        let mut client = TestClient {
            _ctx: client_ctx,
            ssl: client_ssl,
        };

        let mut server = TestClient {
            _ctx: server_ctx,
            ssl: server_ssl,
        };

        for _ in 0..7 {
            let _ = client.ssl.try_negotiate().unwrap();
            let _ = server.ssl.try_negotiate().unwrap();

            client.ssl.io_read_in(server.ssl.io_write_out());
            server.ssl.io_read_in(client.ssl.io_write_out());
        }

        assert!(client.ssl.is_init_finished());
        assert!(server.ssl.is_init_finished());

        (client, server)
    }

    #[test]
    fn try_negotiate() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        // Internally this calls `try_negotiate`
        let _ = make_connected_clients();
    }

    #[test]
    fn try_write_trivial() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);
        const TEXT: &str = "Hello World";

        let (mut client, _server) = make_connected_clients();

        let mut bytes = BytesMut::from(TEXT.as_bytes());

        // Validate that trivial invocations does not break anything
        match client.ssl.try_write(&mut bytes) {
            Ok(Poll::Ready(n)) => {
                assert!(
                    bytes.is_empty(),
                    "Bytes should have been consumed by WolfSSL"
                );
                assert!(
                    !client.ssl.write_buffer().is_empty(),
                    "The write buffer should be populated as a result"
                );
                assert!(
                    client.ssl.read_buffer().is_empty(),
                    "The read buffer should _not_ be populated as a result"
                );
                assert_eq!(
                    n,
                    TEXT.len(),
                    "The number of bytes reported to be written should match"
                );
            }
            x => {
                panic!("Expected bytes to be written! Got {x:?}")
            }
        }
    }

    // Passing in 0 counterintutively results in a WANT_READ/WANT_WRITE instead of an ERROR_NONE
    #[test_case(0 => panics)]
    #[test_case("Hello World".len() => "Hello World".len())]
    #[test_case(TLS_MAX_RECORD_SIZE - 1 => TLS_MAX_RECORD_SIZE - 1)]
    // More than one invocation to `try_read`/`try_write` would be required here
    #[test_case(TLS_MAX_RECORD_SIZE => panics)]
    fn try_read_and_write_roundtrip_once(len: usize) -> usize {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let text = "A".repeat(len);

        let (mut client, mut server) = make_connected_clients();

        let mut client_bytes = BytesMut::from(text.as_bytes());

        assert_eq!(client_bytes.capacity(), len);

        let Ok(Poll::Ready(_)) = client.ssl.try_write(&mut client_bytes) else {
            panic!("Unusual write behavior for this payload");
        };

        server.ssl.io_read_in(client.ssl.io_write_out());

        let mut server_bytes = BytesMut::with_capacity(text.len());

        match server.ssl.try_read(&mut server_bytes) {
            Ok(Poll::Ready(n)) => {
                let read_result = String::from_utf8_lossy(&server_bytes);

                assert_eq!(n, text.len());
                assert_eq!(read_result, text);

                n
            }
            e => panic!("Expected bytes to be read! Got {e:?}"),
        }
    }

    #[test]
    fn try_rehandshake() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let (mut client, mut server) = make_connected_clients_with_method(
            WolfMethod::DtlsClientV1_2,
            WolfMethod::DtlsServerV1_2,
        );

        assert!(client.ssl.is_secure_renegotiation_supported());
        assert!(server.ssl.is_secure_renegotiation_supported());

        const TEST: &str = "foobar";

        for _ in 0..5 {
            let mut bytes = BytesMut::from(TEST.as_bytes());

            // Keep invoking `try_rehandshake` to progress the secure
            // renegotiation.
            match client.ssl.try_rehandshake() {
                Ok(Poll::Ready(_)) => {
                    break;
                }
                Ok(Poll::Pending) => {}
                Ok(Poll::AppData(_)) => {
                    panic!("Should not receive AppData from anywhere")
                }
                Err(e) => panic!("{e}"),
            }

            // While we are here, also test out the Application Data
            // functionality. Lets send some app data while a secure
            // renegotiation is ongoing.
            match client.ssl.try_write(&mut bytes) {
                Ok(Poll::Ready(_) | Poll::Pending) => {}
                Ok(Poll::AppData(_)) => {
                    panic!("Should not receive AppData from anywhere")
                }
                Err(e) => panic!("{e}"),
            };

            server.ssl.io_read_in(client.ssl.io_write_out());

            // We should expect to see on the server side that some application
            // data has been discovered, and that we should get it out or
            // otherwise lose it.
            let mut server_bytes = BytesMut::with_capacity(TEST.len());
            match server.ssl.try_read(&mut server_bytes) {
                Ok(Poll::Ready(_) | Poll::Pending) => {}
                Ok(Poll::AppData(b)) => {
                    assert_eq!(b, TEST);
                    // `server_bytes` should not have been modified if appdata
                    // is discovered.
                    assert!(server_bytes.is_empty());
                }
                Err(e) => panic!("{e}"),
            };

            client.ssl.io_read_in(server.ssl.io_write_out());
        }

        assert!(!client.ssl.is_secure_renegotiation_pending());
        assert!(!server.ssl.is_secure_renegotiation_pending());
    }

    #[test]
    fn try_trigger_update_keys() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let (mut client, mut server) = make_connected_clients_with_method(
            WolfMethod::TlsClientV1_3,
            WolfMethod::TlsServerV1_3,
        );

        assert!(client.ssl.is_tls_13());
        assert!(server.ssl.is_tls_13());

        unsafe {
            wolfssl_sys::wolfSSL_Debugging_ON();
        }

        // Trigger the wolfssl key update mechanism. This will cause the client
        // to send a key update message.
        match client.ssl.try_trigger_update_key() {
            Ok(Poll::Ready(_)) => {}
            Ok(Poll::Pending) => {
                panic!("Should not be pending any data")
            }
            Ok(Poll::AppData(_)) => {
                panic!("Should not receive AppData from anywhere")
            }
            Err(e) => panic!("{e}"),
        }

        assert!(
            client.ssl.is_update_keys_pending(),
            "Client should be expecting a response containing decryption keys"
        );

        let client_send_data = client.ssl.io_write_out();
        assert!(!client_send_data.is_empty());
        server.ssl.io_read_in(client_send_data);

        // The server reads no application data, but this internally triggers
        // some wolfSSL machinery to deal with the key update.
        //
        // This will cause the server to send its own key update message.
        match server.ssl.try_read(&mut BytesMut::with_capacity(0)) {
            Ok(Poll::Pending) => {}
            Ok(Poll::Ready(_)) => {
                panic!("There should be no data to read")
            }
            Ok(Poll::AppData(_)) => {
                panic!("Should not receive AppData from anywhere");
            }
            Err(e) => panic!("{e}"),
        };

        let server_send_data = server.ssl.io_write_out();
        assert!(!server_send_data.is_empty());
        client.ssl.io_read_in(server_send_data);

        // The client also reads no application data, but this will trigger the
        // same key update machinery to occur on the client side.
        match client.ssl.try_read(&mut BytesMut::with_capacity(0)) {
            Ok(Poll::Pending) => {}
            Ok(Poll::Ready(_)) => {
                panic!("There should be no data to read")
            }
            Ok(Poll::AppData(_)) => {
                panic!("Should not receive AppData from anywhere")
            }
            Err(e) => panic!("{e}"),
        };

        assert!(
            !client.ssl.is_update_keys_pending(),
            "Key update should be done within one round trip"
        );
    }
}
