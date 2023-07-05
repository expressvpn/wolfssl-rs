mod data_buffer;

use crate::{
    context::WolfContext,
    error::{Error, Poll, PollResult},
    TLS_MAX_RECORD_SIZE,
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
    pub fn try_negotiate(&self) -> PollResult<()> {
        match unsafe {
            let ssl = self.ssl.lock();
            wolfssl_sys::wolfSSL_negotiate(ssl.as_ptr())
        } {
            wolfssl_sys::WOLFSSL_SUCCESS => Ok(Poll::Ready(())),
            x @ wolfssl_sys::WOLFSSL_FATAL_ERROR => match self.get_error(x) {
                wolfssl_sys::WOLFSSL_ERROR_WANT_READ | wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE => {
                    Ok(Poll::Pending)
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
    pub fn try_shutdown(&self) -> PollResult<()> {
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
    pub fn try_write(&mut self, data_in: &mut BytesMut) -> PollResult<usize> {
        if data_in.is_empty() {
            return Ok(Poll::Ready(0));
        }

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
                wolfssl_sys::WOLFSSL_ERROR_NONE => unreachable!("wolfSSL_write was fed no data"),
                wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE | wolfssl_sys::WOLFSSL_ERROR_WANT_READ => {
                    Ok(Poll::Pending)
                }
                e => Err(Error::fatal(e)),
            },
            _ => unreachable!("Unexpected error code from wolfSSL_write"),
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
    // NOTE: We want to reduce allocations so we accept a buffer to mutate
    // instead of returning a buffer.
    pub fn try_read(&mut self, data_out: &mut BytesMut) -> PollResult<usize> {
        let buf = data_out.spare_capacity_mut();

        // Skip calling into `wolfSSL_read` if there is no space.
        if buf.is_empty() {
            return Ok(Poll::Ready(0));
        }

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
                wolfssl_sys::WOLFSSL_ERROR_NONE => {
                    unreachable!("wolfSSL_read should only be called if buffer has capacity")
                }
                e => Err(Error::fatal(e)),
            },
            _ => unreachable!("Unexpected error from wolfSSL_read"),
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

        for _ in 0..4 {
            let _ = client.ssl.try_negotiate().unwrap();
            let _ = server.ssl.try_negotiate().unwrap();

            client.ssl.io_read_in(server.ssl.io_write_out());
            server.ssl.io_read_in(client.ssl.io_write_out());
        }

        // The handshake should complete in 4 rounds.
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

    #[test_case(0 => 0)]
    #[test_case("Hello World".len() => "Hello World".len())]
    #[test_case(TLS_MAX_RECORD_SIZE - 1 => TLS_MAX_RECORD_SIZE - 1)]
    // More than one invocation to `try_read`/`try_write` would be required here
    #[test_case(TLS_MAX_RECORD_SIZE => panics)]
    fn try_read_and_write_roundtrip_once(len: usize) -> usize {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let text = "A".repeat(len);

        let (mut client, mut server) = make_connected_clients();

        let mut client_bytes = BytesMut::from(text.as_bytes());

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
}
