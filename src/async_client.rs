//! This module attempts to implement `AsyncRead` and `AsyncWrite` for
//! `WolfSession`.
//!
//! WolfSSL has 2 ways of registering an input/output facility for the
//! SSL connection:
//! 1. File descriptors, via [`wolfSSL_set_fd`][0].
//!    - This seems feasible with tokio since at least
//!      [`TcpStream`][5] allows direct access of the raw file
//!      descriptor
//! 2. Custom IO callbacks, via a workflow enabled by an assortment of
//!    functions that operate roughly like this:
//!    - Register a callback at the `WOLFSSL_CTX` (context) level via
//!      [`wolfSSL_CTX_SetIORecv`][1] and/or
//!      `wolfSSL_CTX_SetIOSend` (online docs not found, unfortunately).
//!    - Register a `void* ctx` object on the `WOLFSSL` (session) level
//!      via [`wolfSSL_SetIOWriteCtx`][2] and/or
//!      `wolfSSL_SetIOReadCtx`.
//!    - Whenever a `WOLFSSL` ptr calls [`wolfSSL_read`][3] or
//!      [`wolfSSL_write`][4] the context-level callbacks get
//!      invoked with session-level `void* ctx` payloads.
//!
//! [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_set_fd
//! [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_ctx_setiorecv
//! [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setioreadctx
//! [3]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_read
//! [4]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_write
//! [5]: https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#impl-AsRawFd-for-TcpStream

use crate::{errors::WolfError, WolfContext, WolfContextBuilder, WolfSession};

use bytes::{Buf, BytesMut};
use pin_project::pin_project;
use std::{
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing_attributes::instrument;

/// Record size is defined as `2^14 + 1`.
///
/// > ...the full encoded TLSInnerPlaintext MUST NOT exceed 2^14 + 1
/// > octets
/// - [source][0]
///
/// This value must also equal or exceed `<wolfssl/internal.h>`'s
/// `MAX_RECORD_SIZE` (though I'm not sure how to assert that yet).
///
/// [0]: https://www.rfc-editor.org/rfc/rfc8446#section-5.4
const TLS_MAX_RECORD_SIZE: usize = 2usize.pow(14) + 1;

/// The struct that will be passed into the `ctx` variable (as a
/// `void*`) of the wolfssl ctx callbacks.
#[derive(Debug)]
pub(crate) struct WolfClientCallbackContext {
    /// To be read into callback buffer, and read from the internal
    /// stream
    read_buffer: BytesMut,
    /// to be written from the callback buffer, and written into the
    /// internal stream
    write_buffer: BytesMut,
}

/// The core wrapper around a stream that implements [`AsyncRead`] and
/// [`AsyncWrite`].
///
/// Currently it must be a stream that implements both, but in the
/// future we might want to relax this constraint.
// Lets do 1:1 context/session for now, and punt the design complexity
// of having to manage different contexts to later.
#[pin_project]
pub struct WolfClient<T: AsyncRead + AsyncWrite + Unpin> {
    // NOTE (pangt): contexts carry process-level defaults and this is
    // actually bad design: Each context should be able to spawn off
    // clients, which carry a copy of the context around
    #[pin]
    pub(crate) _ssl_context: WolfContext,
    #[pin]
    pub(crate) ssl_session: WolfSession,
    #[pin]
    session_context: Box<WolfClientCallbackContext>,
    #[pin]
    stream: T,
}

impl<T: AsyncRead + AsyncWrite + Unpin> std::fmt::Debug for WolfClient<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WolfClient").finish_non_exhaustive()
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug> WolfClient<T> {
    /// Takes in a context and registers additional callbacks that
    /// allows for asynchronous IO.
    #[instrument(level = "Debug")]
    // We take in a `WolfContextBuilder` because we might want to
    // eventually convert all these additional unsafe callbacks into
    // builder methods. Time will tell.
    pub fn new_with_context_and_stream(builder: WolfContextBuilder, stream: T) -> Result<Self, ()> {
        let ssl_context = builder.build();

        // register context-side callbacks
        unsafe {
            wolfssl_sys::wolfSSL_CTX_SetIORecv(ssl_context.ctx, Some(wolf_tls_read_cb));
            wolfssl_sys::wolfSSL_CTX_SetIOSend(ssl_context.ctx, Some(wolf_tls_write_cb));
        }

        let session_context = Box::new(WolfClientCallbackContext {
            read_buffer: BytesMut::with_capacity(TLS_MAX_RECORD_SIZE),
            write_buffer: BytesMut::with_capacity(TLS_MAX_RECORD_SIZE),
        });

        // Create a new SSL session and register session-side
        // callbacks
        let ssl_session = ssl_context
            .new_session()
            .expect("ssl_context.new_session()");

        let mut client = Self {
            _ssl_context: ssl_context,
            ssl_session,
            session_context,
            stream,
        };

        client
            .ssl_session
            .set_io_context(&mut client.session_context);

        Ok(client)
    }

    async fn try_accept(&mut self) -> IoResult<bool> {
        match self.ssl_session.try_accept() {
            Ok(()) | Err(WolfError::WantRead | WolfError::WantWrite) => {}
            Err(err @ WolfError::Unknown { .. }) => {
                return Err(IoError::new(IoErrorKind::Other, err))
            }
        }

        use tokio::io::AsyncWriteExt;
        // Now make what's visible to wolfssl, also visible to the stream
        self.flush().await?;

        if self.ssl_session.is_init_finished() {
            Ok(true)
        } else {
            // If there is something in the stream not yet visible to
            // wolfssl, try making it visible.
            self.fill_read_buffer_from_stream().await?;
            Ok(false)
        }
    }

    async fn try_connect(&mut self) -> IoResult<bool> {
        match self.ssl_session.try_connect() {
            Ok(()) | Err(WolfError::WantRead | WolfError::WantWrite) => {}
            Err(err @ WolfError::Unknown { .. }) => {
                return Err(IoError::new(IoErrorKind::Other, err))
            }
        }

        use tokio::io::AsyncWriteExt;
        // Now make what's visible to wolfssl, also visible to the stream
        self.flush().await?;

        if self.ssl_session.is_init_finished() {
            Ok(true)
        } else {
            // If there is something in the stream not yet visible to
            // wolfssl, try making it visible.
            self.fill_read_buffer_from_stream().await?;
            Ok(false)
        }
    }

    async fn try_negotiate(&mut self) -> IoResult<bool> {
        match self.ssl_session.try_negotiate() {
            Ok(()) | Err(WolfError::WantRead | WolfError::WantWrite) => {}
            Err(err @ WolfError::Unknown { .. }) => {
                return Err(IoError::new(IoErrorKind::Other, err));
            }
        }

        // Now make what's visible to wolfssl, also visible to the stream
        use tokio::io::AsyncWriteExt;
        self.flush().await?;

        if self.ssl_session.is_init_finished() {
            Ok(true)
        } else {
            // If there is something in the stream not yet visible to
            // wolfssl, try making it visible.
            self.fill_read_buffer_from_stream().await?;
            Ok(false)
        }
    }

    /// As a client, connect to a server.
    pub async fn connect(&mut self) -> IoResult<()> {
        while !self.ssl_session.is_init_finished() {
            self.try_connect().await?;
        }
        Ok(())
    }

    /// As a server, accept a connection.
    ///
    /// `wolfSSL_accept` does not block until the the connection is
    /// formed, and generally requires multiple invocations to
    /// complete the handshake. This method invokes `wolfSSL_accept`
    /// as many times as necessary.
    pub async fn accept(&mut self) -> IoResult<()> {
        while !self.ssl_session.is_init_finished() {
            self.try_accept().await?;
        }
        Ok(())
    }

    /// Connect/Accept depending on how the `WOLFSSL_CTX` method is set.
    pub async fn negotiate(&mut self) -> IoResult<()> {
        while !self.ssl_session.is_init_finished() {
            self.try_negotiate().await?;
        }
        Ok(())
    }
}

/// The custom IO callback documented at [`EmbedRecieve`][0] (whose
/// inputs and outputs we need to emulate).
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-embedreceive
#[allow(dead_code)]
extern "C" fn wolf_tls_read_cb(
    _ssl: *mut wolfssl_sys::WOLFSSL,
    buf: *mut ::std::os::raw::c_char,
    sz: ::std::os::raw::c_int,
    ctx: *mut ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
    let read_buffer = {
        let context = unsafe { &mut *(ctx as *mut WolfClientCallbackContext) };
        &mut context.read_buffer
    };

    // If the buffer is empty, there's nothing more to do here. Tell
    // WolfSSL that we need more data
    if read_buffer.is_empty() {
        return wolfssl_sys::IOerrors_WOLFSSL_CBIO_ERR_WANT_READ;
    }

    // Find out how much we should or can copy to WolfSSL. WolfSSL
    // asks for data piecemeal, so often it will ask for just 2 or 5
    // bytes at a time. Passing more will cause it to error. On the
    // other hand though, it might need a 1000 bytes, but all we have
    // is 500 - in which case just send all that we can.
    let num_of_bytes = std::cmp::min(read_buffer.len(), sz as usize);

    // Now for some slight of hand - make the buffer provided by
    // WolfSSL appear as a slice. Despite this being an unsafe piece
    // of code, it will make further interactions far safer by
    // conceptualising the buffer pointer and length together.
    //
    // We use `num_of_bytes` here to ensure that we are always dealing
    // with valid memory
    let wolf_buffer = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, num_of_bytes) };

    // Copy the data into WolfSSL's buffer
    wolf_buffer.copy_from_slice(&read_buffer[..num_of_bytes]);

    // Drop the bytes read into WolfSSL
    Buf::advance(read_buffer, num_of_bytes);

    // WolfSSL expects that we return the number of bytes copied
    num_of_bytes as ::std::os::raw::c_int
}

/// The custom IO callback documented at [`EmbedSend`][0] (whose
/// inputs and outputs we need to emulate).
///
/// Here the assumption is that WolfSSL is writing data _into_ the
/// callback (which will then ship it off somewhere)
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-embedsend
#[allow(dead_code)]
extern "C" fn wolf_tls_write_cb(
    _ssl: *mut wolfssl_sys::WOLFSSL,
    buf: *mut ::std::os::raw::c_char,
    sz: ::std::os::raw::c_int,
    ctx: *mut ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
    let write_buffer = {
        let context = unsafe { &mut *(ctx as *mut WolfClientCallbackContext) };
        &mut context.write_buffer
    };

    // Create a slice using the c pointer and length from WolfSSL.
    // This contains the bytes we need to write out
    let wolf_buffer: &[u8] = unsafe { std::slice::from_raw_parts(buf as *const u8, sz as usize) };

    // Copy bytes into our write buffer. Our buffer will resize as
    // needed
    write_buffer.extend_from_slice(wolf_buffer);

    // Return the number of bytes WolfSSL gave us as we can consume
    // all of them. At this point however WolfSSL believes that the
    // send was successful, it has no way to know otherwise
    wolf_buffer.len() as ::std::os::raw::c_int
}

#[derive(Debug)]
enum FillReadBuffer {
    Ok(Poll<IoResult<()>>),
    EndOfFile,
}

impl<T: AsyncRead + AsyncWrite + Unpin> WolfClient<T> {
    /// Handles the polling of bytes from the inner stream.
    /// The bytes will then
    fn fill_read_buffer(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> FillReadBuffer {
        let mut extract_buffer = BytesMut::zeroed(TLS_MAX_RECORD_SIZE);

        let remaining = std::cmp::min(
            extract_buffer.len(),
            self.session_context.read_buffer.capacity(),
        );

        let mut encrypted_buffer = ReadBuf::new(&mut extract_buffer[..remaining]);

        assert!(
            encrypted_buffer.filled().is_empty(),
            "EOF checks assume this invariant"
        );

        match Pin::new(&mut self.stream).poll_read(cx, &mut encrypted_buffer) {
            Poll::Ready(Ok(())) if encrypted_buffer.filled().is_empty() => {
                // Per `poll_read` API contract
                FillReadBuffer::EndOfFile
            }
            x @ Poll::Ready(Ok(())) if !encrypted_buffer.filled().is_empty() => {
                self.session_context
                    .read_buffer
                    .extend_from_slice(encrypted_buffer.filled());
                FillReadBuffer::Ok(x)
            }
            x => FillReadBuffer::Ok(x),
        }
    }

    fn decode_read_buffer(self: Pin<&mut Self>) -> Result<Vec<u8>, WolfError> {
        let mut temp_plaintext_buffer_backing = BytesMut::zeroed(TLS_MAX_RECORD_SIZE);
        let mut temp_plaintext_buffer = ReadBuf::new(&mut temp_plaintext_buffer_backing);

        let result = loop {
            match self.ssl_session.read_into(&mut temp_plaintext_buffer) {
                Ok(_) => {}
                Err(WolfError::WantRead) => {
                    break Ok(temp_plaintext_buffer.filled().to_vec());
                }
                Err(WolfError::WantWrite) => {
                    panic!("This implementation assumes that wolfSSL_read will never want to write something");
                }
                Err(err @ WolfError::Unknown { .. }) => break Err(err),
            }
        };
        result
    }

    async fn fill_read_buffer_from_stream(&mut self) -> IoResult<()> {
        use tokio::io::AsyncReadExt;

        self.stream
            .read_buf(&mut self.session_context.read_buffer)
            .await?;

        Ok(())
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for WolfClient<T> {
    /// The internal stream we manage can only pass us a ciphertext
    /// stream, which we must then decrypt via `wolfSSL_read` to
    /// extract the plaintext.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        let mut plaintext_buffer = BytesMut::new();

        let result = loop {
            match self.as_mut().decode_read_buffer() {
                Ok(plaintext) if plaintext.is_empty() => {}
                // Immediately return what we have decoded. This is to
                // ensure that we don't run into the scenario where we
                // are forced to signal `Poll::Pending` even if we
                // have decoded bytes ready (and should return
                // `Poll::Ready`).
                Ok(plaintext) => {
                    plaintext_buffer.extend_from_slice(&plaintext);
                    break Poll::Ready(Ok(()));
                }
                Err(e) => {
                    break Poll::Ready(Err(IoError::new(IoErrorKind::Other, e)));
                }
            }

            match self.as_mut().fill_read_buffer(cx) {
                // Even if the read buffer is non-empty, it's a
                // fragment of some frame that we can no longer decode
                FillReadBuffer::EndOfFile => {
                    break Poll::Ready(Ok(()));
                }
                // If we pulled something then we should try decoding again.
                FillReadBuffer::Ok(Poll::Ready(Ok(()))) => {
                    assert!(!self.session_context.read_buffer.is_empty());
                }
                FillReadBuffer::Ok(x @ Poll::Pending) => break x,
                FillReadBuffer::Ok(x @ Poll::Ready(Err(_))) => {
                    break x;
                }
            }
        };

        buf.put_slice(&plaintext_buffer);

        result
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> WolfClient<T> {
    /// Move the bytes currently residing in the write buffer into the
    /// internal stream.
    ///
    /// An important implementation detail here is that we pretend
    /// that this is an all-or-nothing operation. To the runtime, we
    /// either fully wrote the buffer or are waiting to.
    fn write_into_stream(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<usize>> {
        let submit = self.session_context.write_buffer.clone().freeze();
        let pinned = Pin::new(&mut self.stream);
        match pinned.poll_write(cx, &submit) {
            Poll::Pending => {
                // We let the underlying stream register the waker,
                // maintaining the Poll contract
                Poll::Pending
            }
            Poll::Ready(Ok(written)) if written == self.session_context.write_buffer.len() => {
                self.session_context.write_buffer.clear();
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Ok(written)) => {
                let _written_chunk = self.session_context.write_buffer.split_to(written);

                // We immediately reschedule the task since the
                // underlying stream might still be available for
                // writing.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            err @ Poll::Ready(Err(_)) => err,
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WolfClient<T> {
    /// Write some data into the underlying stream [`WolfClient`] is
    /// wrapping.
    ///
    /// # Details
    /// Since this is a secure connection, we will need to encrypt the
    /// data; This is done by running it through `wolfSSL_write`.
    ///
    /// The encrypted result will end up in the send buffers we
    /// maintain via registered custom IO callbacks, which is the
    /// actual data we send into the underlying stream.
    ///
    /// Because of how the [`AsyncWrite` API][0] contract works, this
    /// fn will only ever return `buf.len()` if it returns
    /// `Ready(Ok(_))`. Refer to comment in source for more details.
    ///
    /// [0]: https://docs.rs/tokio/latest/tokio/io/trait.AsyncWrite.html#tymethod.poll_write
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        let write_result = match self.ssl_session.write(buf) {
            Ok(bytes_written) => Poll::Ready(Ok(bytes_written)),
            Err(err) => Poll::Ready(Err(IoError::new(IoErrorKind::Other, err))),
        };

        let result = match self.as_mut().write_into_stream(cx) {
            // ** PLEASE UNDERSTAND THIS **
            //
            // The actual number of bytes written by us will not be
            // the same as the number of bytes our caller will think
            // we have written.
            //
            // This is because we encrypt the bytes the caller passes
            // to us first, altering its actual size.
            //
            // However, now we have to consider a few things:
            // - We cannot tell, looking at the encrypted bytes, how
            //   much bytes have been partially sent.
            //
            //   We solve this by only returning `Poll::Ready(Ok(_))`
            //   once the entire buffer has been sent, never a partial
            //   resumable value.
            //
            // - The `poll_write` API only allows a valid
            //   return value of 0 <= n <= buf.len().
            //
            // We solve these two things by only ever returning
            // `Ok(buf.len())` as an `Ok` value.
            //
            Poll::Ready(Ok(_enc_bytes_written)) => write_result,
            x => x,
        };

        if let Poll::Ready(Ok(n)) = &result {
            assert_eq!(*n, buf.len(), "");
        }

        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        if !self.session_context.write_buffer.is_empty() {
            match self.as_mut().write_into_stream(cx) {
                x @ (Poll::Ready(Err(_)) | Poll::Pending) => return x.map_ok(|_| ()),
                Poll::Ready(Ok(_)) => {}
            }
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        // The API contract for shutting down a stream requires
        // flushing it.
        if !self.session_context.write_buffer.is_empty() {
            match self.as_mut().write_into_stream(cx) {
                x @ (Poll::Ready(Err(_)) | Poll::Pending) => return x.map_ok(|_| ()),
                Poll::Ready(Ok(_)) => {}
            }
        }
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{CA_CERT, INIT_ENV_LOGGER, SERVER_CERT, SERVER_KEY};
    use test_case::test_case;
    use tokio::{
        io::{duplex, AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    #[tokio::test]
    async fn custom_io_callbacks_accept_and_connect_over_tcp() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        crate::wolf_init().unwrap();

        let client_builder = WolfContextBuilder::new(crate::WolfMethod::TlsClient)
            .unwrap()
            .with_root_certificate(crate::RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap();

        let server_builder = WolfContextBuilder::new(crate::WolfMethod::TlsServer)
            .unwrap()
            .with_certificate(crate::Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(crate::Secret::Asn1Buffer(SERVER_KEY))
            .unwrap();

        // setting the port to 0 lets the OS figure out what port to give us.
        let server_conn = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_conn.local_addr().unwrap();

        let client = async move {
            let client_conn = TcpStream::connect(server_addr)
                .await
                .expect("client TcpStream::connect");

            let mut client =
                WolfClient::new_with_context_and_stream(client_builder, client_conn).unwrap();

            client.connect().await.expect("client.connect()");
            client
        };

        let server = async move {
            let (server_conn, _) = server_conn.accept().await.expect("server_conn.accept");

            let mut server =
                WolfClient::new_with_context_and_stream(server_builder, server_conn).unwrap();

            server.accept().await.expect("server.accept()");
            server
        };

        let (client, server) = tokio::join!(client, server);

        assert!(client.session_context.read_buffer.is_empty());
        assert!(client.session_context.write_buffer.is_empty());

        assert!(server.session_context.read_buffer.is_empty());
        assert!(server.session_context.write_buffer.is_empty());
    }

    #[tokio::test]
    async fn custom_io_callbacks_accept_and_connect_in_memory() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        crate::wolf_init().unwrap();

        let client_builder = WolfContextBuilder::new(crate::WolfMethod::TlsClient)
            .unwrap()
            .with_root_certificate(crate::RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap();

        let server_builder = WolfContextBuilder::new(crate::WolfMethod::TlsServer)
            .unwrap()
            .with_certificate(crate::Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(crate::Secret::Asn1Buffer(SERVER_KEY))
            .unwrap();

        let (client_conn, server_conn) = duplex(usize::MAX);

        let client = async move {
            let mut client =
                WolfClient::new_with_context_and_stream(client_builder, client_conn).unwrap();

            client.connect().await.expect("client.connect()");
            client
        };

        let server = async move {
            let mut server =
                WolfClient::new_with_context_and_stream(server_builder, server_conn).unwrap();

            server.accept().await.expect("server.accept()");
            server
        };

        let (client, server) = tokio::join!(client, server);

        assert!(client.session_context.read_buffer.is_empty());
        assert!(client.session_context.write_buffer.is_empty());

        assert!(server.session_context.read_buffer.is_empty());
        assert!(server.session_context.write_buffer.is_empty());
    }

    #[tokio::test]
    async fn custom_io_callbacks_negotiate_over_tcp() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        crate::wolf_init().unwrap();

        let client_builder = WolfContextBuilder::new(crate::WolfMethod::TlsClient)
            .unwrap()
            .with_root_certificate(crate::RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap();

        let server_builder = WolfContextBuilder::new(crate::WolfMethod::TlsServer)
            .unwrap()
            .with_certificate(crate::Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(crate::Secret::Asn1Buffer(SERVER_KEY))
            .unwrap();

        // setting the port to 0 lets the OS figure out what port to give us.
        let server_conn = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_conn.local_addr().unwrap();

        let client = async move {
            let client_conn = TcpStream::connect(server_addr)
                .await
                .expect("client TcpStream::connect");

            let mut client =
                WolfClient::new_with_context_and_stream(client_builder, client_conn).unwrap();

            client.negotiate().await.expect("client.connect()");
            client
        };

        let server = async move {
            let (server_conn, _) = server_conn.accept().await.expect("server_conn.accept");

            let mut server =
                WolfClient::new_with_context_and_stream(server_builder, server_conn).unwrap();

            server.negotiate().await.expect("server.accept()");
            server
        };

        let (client, server) = tokio::join!(client, server);

        assert!(client.session_context.read_buffer.is_empty());
        assert!(client.session_context.write_buffer.is_empty());

        assert!(server.session_context.read_buffer.is_empty());
        assert!(server.session_context.write_buffer.is_empty());
    }

    #[tokio::test]
    async fn custom_io_callbacks_negotiate_in_memory() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        crate::wolf_init().unwrap();

        let client_builder = WolfContextBuilder::new(crate::WolfMethod::TlsClient)
            .unwrap()
            .with_root_certificate(crate::RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap();

        let server_builder = WolfContextBuilder::new(crate::WolfMethod::TlsServer)
            .unwrap()
            .with_certificate(crate::Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(crate::Secret::Asn1Buffer(SERVER_KEY))
            .unwrap();

        let (client_conn, server_conn) = duplex(usize::MAX);

        let client = async move {
            let mut client =
                WolfClient::new_with_context_and_stream(client_builder, client_conn).unwrap();

            client.negotiate().await.expect("client.connect()");
            client
        };

        let server = async move {
            let mut server =
                WolfClient::new_with_context_and_stream(server_builder, server_conn).unwrap();

            server.negotiate().await.expect("server.accept()");
            server
        };

        let (client, server) = tokio::join!(client, server);

        assert!(client.session_context.read_buffer.is_empty());
        assert!(client.session_context.write_buffer.is_empty());

        assert!(server.session_context.read_buffer.is_empty());
        assert!(server.session_context.write_buffer.is_empty());
    }

    #[tokio::test]
    async fn custom_io_callbacks_negotiate_in_memory_tiny_stream() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        crate::wolf_init().unwrap();

        let client_builder = WolfContextBuilder::new(crate::WolfMethod::TlsClient)
            .unwrap()
            .with_root_certificate(crate::RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap();

        let server_builder = WolfContextBuilder::new(crate::WolfMethod::TlsServer)
            .unwrap()
            .with_certificate(crate::Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(crate::Secret::Asn1Buffer(SERVER_KEY))
            .unwrap();

        // Set the size of the pipe to 1 byte to force a lot more `Poll::Pending`s
        let (client_conn, server_conn) = duplex(1);

        let client = async move {
            let mut client =
                WolfClient::new_with_context_and_stream(client_builder, client_conn).unwrap();

            client.negotiate().await.expect("client.connect()");
            client
        };

        let server = async move {
            let mut server =
                WolfClient::new_with_context_and_stream(server_builder, server_conn).unwrap();

            server.negotiate().await.expect("server.accept()");
            server
        };

        let (client, server) = tokio::join!(client, server);

        assert!(client.session_context.read_buffer.is_empty());
        assert!(client.session_context.write_buffer.is_empty());

        assert!(server.session_context.read_buffer.is_empty());
        assert!(server.session_context.write_buffer.is_empty());
    }

    /// Spawn a server on a separate thread, then have the client send
    /// something to it. For convenience send it back again and
    /// perform the assertion on the main thread.
    #[tokio::test]
    async fn custom_io_callbacks_hello_world_in_memory() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        const MESSAGE: &str = "hello world!";

        crate::wolf_init().unwrap();

        let client_builder = WolfContextBuilder::new(crate::WolfMethod::TlsClient)
            .expect("client WolfBuilder")
            .with_root_certificate(crate::RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap();

        let server_builder = WolfContextBuilder::new(crate::WolfMethod::TlsServer)
            .expect("new(crate::WolfMethod::TlsServer)")
            .with_certificate(crate::Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(crate::Secret::Asn1Buffer(SERVER_KEY))
            .expect("server WolfBuilder");

        let (client_conn, server_conn) = duplex(usize::MAX);

        let client = async move {
            let mut client = {
                WolfClient::new_with_context_and_stream(client_builder, client_conn)
                    .expect("client WolfClient")
            };

            client.negotiate().await.expect("client.negotiate");

            assert!(client.ssl_session.is_init_finished());

            // write then read

            client
                .write_all(MESSAGE.as_bytes())
                .await
                .expect("client.write_all");

            let mut recv_string = String::new();
            client
                .read_to_string(&mut recv_string)
                .await
                .expect("client.read_to_string");

            assert_eq!(
                MESSAGE, recv_string,
                "Expected '{MESSAGE}' but got {recv_string:?}"
            );
        };

        let server = async move {
            let mut server = WolfClient::new_with_context_and_stream(server_builder, server_conn)
                .expect("server WolfClient");

            server.negotiate().await.expect("server.negotiate");

            assert!(server.ssl_session.is_init_finished());

            // read then write

            let mut recv_buffer = vec![0u8; MESSAGE.len()];
            server
                .read_exact(&mut recv_buffer)
                .await
                .expect("server.read_exact");

            assert_eq!(String::from_utf8(recv_buffer.clone()).unwrap(), MESSAGE);

            server
                .write_all(&recv_buffer)
                .await
                .expect("server.write_all");
        };

        tokio::join!(client, server);
    }

    // TODO (pangt): Figure out how the following cases scale as
    // the length of `MESSAGE` changes
    #[test_case(1  => ignore["fails with deadlock"])]
    #[test_case(25 => ignore["fails with deadlock"])]
    #[test_case(37 => ignore["fails with `Kind(BrokenPipe)` error"])]
    #[test_case(44 => ignore["fails with `Kind(BrokenPipe)` error"])]
    #[test_case(45 => ignore["fails with `panicked at 'buf.len() must fit in remaining()'` error"])]
    #[test_case(46)] // works from this value onwards
    #[tokio::test]
    async fn custom_io_callbacks_hello_world_in_memory_tiny_stream(stream_buffer_size: usize) {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        const MESSAGE: &str = "hello world!";

        crate::wolf_init().unwrap();

        let client_builder = WolfContextBuilder::new(crate::WolfMethod::TlsClient)
            .expect("client WolfBuilder")
            .with_root_certificate(crate::RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap();

        let server_builder = WolfContextBuilder::new(crate::WolfMethod::TlsServer)
            .expect("new(crate::WolfMethod::TlsServer)")
            .with_certificate(crate::Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(crate::Secret::Asn1Buffer(SERVER_KEY))
            .expect("server WolfBuilder");
        let (client_conn, server_conn) = duplex(stream_buffer_size);

        let client = async move {
            let mut client = {
                WolfClient::new_with_context_and_stream(client_builder, client_conn)
                    .expect("client WolfClient")
            };

            client.negotiate().await.expect("client.negotiate");

            assert!(client.ssl_session.is_init_finished());

            // write then read

            client
                .write_all(MESSAGE.as_bytes())
                .await
                .expect("client.write_all");

            let mut recv_string = String::new();
            client
                .read_to_string(&mut recv_string)
                .await
                .expect("client.read_to_string");

            assert_eq!(
                MESSAGE, recv_string,
                "Expected '{MESSAGE}' but got {recv_string:?}"
            );
        };

        // Run the server on a separate thread
        let server = async move {
            let mut server = WolfClient::new_with_context_and_stream(server_builder, server_conn)
                .expect("server WolfClient");

            server.negotiate().await.expect("server.negotiate");

            assert!(server.ssl_session.is_init_finished());

            // read then write

            let mut recv_buffer = vec![0u8; MESSAGE.len()];
            server
                .read_exact(&mut recv_buffer)
                .await
                .expect("server.read_exact");

            assert_eq!(String::from_utf8(recv_buffer.clone()).unwrap(), MESSAGE);

            server
                .write_all(&recv_buffer)
                .await
                .expect("server.write_all");

            server.flush().await.unwrap();
        };

        tokio::join!(client, server);
    }

    /// Spawn a server on a separate thread, then have the client send
    /// something to it. For convenience send it back again and
    /// perform the assertion on the main thread.
    #[tokio::test]
    async fn custom_io_callbacks_hello_world_over_tcp() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        const MESSAGE: &str = "hello world!";

        crate::wolf_init().unwrap();

        let client_builder = WolfContextBuilder::new(crate::WolfMethod::TlsClient)
            .expect("client WolfBuilder")
            .with_root_certificate(crate::RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap();

        let server_builder = WolfContextBuilder::new(crate::WolfMethod::TlsServer)
            .expect("new(crate::WolfMethod::TlsServer)")
            .with_certificate(crate::Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(crate::Secret::Asn1Buffer(SERVER_KEY))
            .expect("server WolfBuilder");

        // setting the port to 0 lets the OS figure out what port to give us.
        let server_conn = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_conn.local_addr().unwrap();

        let client = async move {
            let client_conn = TcpStream::connect(server_addr)
                .await
                .expect("client TcpStream::connect");

            let mut client = {
                WolfClient::new_with_context_and_stream(client_builder, client_conn)
                    .expect("client WolfClient")
            };

            client.negotiate().await.expect("client.negotiate");

            assert!(client.ssl_session.is_init_finished());

            // write then read

            client
                .write_all(MESSAGE.as_bytes())
                .await
                .expect("client.write_all");

            let mut recv_string = String::new();
            client
                .read_to_string(&mut recv_string)
                .await
                .expect("client.read_to_string");

            assert_eq!(
                MESSAGE, recv_string,
                "Expected '{MESSAGE}' but got {recv_string:?}"
            );
        };

        let server = async move {
            let (server_conn, _) = server_conn.accept().await.expect("server_conn.accept");

            let mut server = WolfClient::new_with_context_and_stream(server_builder, server_conn)
                .expect("server WolfClient");

            server.negotiate().await.expect("server.negotiate");

            assert!(server.ssl_session.is_init_finished());

            // read then write

            let mut recv_buffer = vec![0u8; MESSAGE.len()];
            server
                .read_exact(&mut recv_buffer)
                .await
                .expect("server.read_exact");

            assert_eq!(String::from_utf8(recv_buffer.clone()).unwrap(), MESSAGE);

            server
                .write_all(&recv_buffer)
                .await
                .expect("server.write_all");
        };

        tokio::join!(client, server);
    }
}
