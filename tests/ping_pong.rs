#![deny(unsafe_code)] // unsafety should all be in the library.

use wolfssl::{ContextBuilder, IOCallbacks, Protocol, RootCertificate, Secret, SessionConfig};

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::net::{UnixDatagram, UnixStream};

const CA_CERT: &[u8] = &include!("data/ca_cert_der_2048");
const SERVER_CERT: &[u8] = &include!("data/server_cert_der_2048");
const SERVER_KEY: &[u8] = &include!("data/server_key_der_2048");

#[async_trait]
trait SockIO {
    async fn ready(&self, interest: tokio::io::Interest) -> std::io::Result<tokio::io::Ready>;

    fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn try_send(&self, buf: &[u8]) -> std::io::Result<usize>;
}

struct SockIOCallbacks<IOCB: SockIO>(std::rc::Rc<IOCB>);

// `#[derive(Clone)]` insists on `IOCB` being `Clone`, which isn't needed due to our `Rc`
impl<IOCB: SockIO> Clone for SockIOCallbacks<IOCB> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<IOCB: SockIO> SockIOCallbacks<IOCB> {
    async fn wait_read(&self, who: &'static str, what: &'static str) {
        println!("[{who}] {what}: Poll for read");
        let readiness = self
            .0
            .ready(tokio::io::Interest::READABLE)
            .await
            .unwrap_or_else(|_| panic!("[{who}] {what}: Poll for read"));
        println!("[{who}] {what}: Socket is ready: {readiness:?}");
    }

    async fn wait_write(&self, who: &'static str, what: &'static str) {
        println!("[{who}] {what}: Poll for write");
        let readiness = self
            .0
            .ready(tokio::io::Interest::WRITABLE)
            .await
            .unwrap_or_else(|_| panic!("[{who}] {what}: Poll for write"));
        println!("[{who}] {what}: Socket is ready: {readiness:?}");
    }
}

impl<IOCB: SockIO> IOCallbacks for SockIOCallbacks<IOCB> {
    fn recv(&self, buf: &mut [u8]) -> wolfssl::IOCallbackResult<usize> {
        match self.0.try_recv(buf) {
            Ok(nr) => wolfssl::IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                wolfssl::IOCallbackResult::WouldBlock
            }
            Err(err) => wolfssl::IOCallbackResult::Err(err),
        }
    }

    fn send(&self, buf: &[u8]) -> wolfssl::IOCallbackResult<usize> {
        match self.0.try_send(buf) {
            Ok(nr) => wolfssl::IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                wolfssl::IOCallbackResult::WouldBlock
            }
            Err(err) => wolfssl::IOCallbackResult::Err(err),
        }
    }
}

#[async_trait]
impl SockIO for tokio::net::UnixDatagram {
    async fn ready(&self, interest: tokio::io::Interest) -> std::io::Result<tokio::io::Ready> {
        Self::ready(self, interest).await
    }

    fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        Self::try_recv(self, buf)
    }

    fn try_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        Self::try_send(self, buf)
    }
}

#[async_trait]
impl SockIO for tokio::net::UnixStream {
    async fn ready(&self, interest: tokio::io::Interest) -> std::io::Result<tokio::io::Ready> {
        Self::ready(self, interest).await
    }

    fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        Self::try_read(self, buf)
    }

    fn try_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        Self::try_write(self, buf)
    }
}

async fn client<S: SockIO>(sock: S, protocol: Protocol) {
    let sock = std::rc::Rc::new(sock);

    let ca_cert = RootCertificate::Asn1Buffer(CA_CERT);

    let ctx = ContextBuilder::new(protocol)
        .expect("[Client] new ContextBuilder")
        .with_root_certificate(ca_cert)
        .expect("[Client] add root certificate")
        .build();

    let io = SockIOCallbacks(sock);
    let session_config = SessionConfig::new(io.clone()).with_dtls_nonblocking(true);
    let mut session = ctx
        .new_session(session_config)
        .expect("[Client] Create Client SSL session");

    println!("[Client] Connecting...");
    'negotiate: loop {
        match session.try_negotiate().expect("[Client] try_negotiate") {
            wolfssl::Poll::PendingRead => io.wait_read("Client", "Negotiate").await,
            wolfssl::Poll::PendingWrite => io.wait_write("Client", "Negotiate").await,
            wolfssl::Poll::Ready(_) => {
                println!("[Client] Negotiation complete!");
                break 'negotiate;
            }
            wolfssl::Poll::AppData(_b) => todo!("[Client] Handle App Data"),
        }
    }

    assert!(session.is_init_finished());

    println!("[Client] Starting ping/pong loop");

    let mut buf = BytesMut::with_capacity(1900);

    for ping in ["Hello", /*"Goodbye",*/ "QUIT"] {
        println!("[Client] Send {ping}");

        let mut ping: BytesMut = ping.into();
        let _nr = 'send: loop {
            match session.try_write(&mut ping).expect("[Client] try_write") {
                wolfssl::Poll::PendingRead => io.wait_read("Client", "Write").await,
                wolfssl::Poll::PendingWrite => io.wait_write("Client", "Write").await,
                wolfssl::Poll::Ready(nr) => {
                    println!("[Client] Write {nr} complete!");
                    break 'send nr;
                }
                wolfssl::Poll::AppData(_b) => todo!("[Client] Handle App Data"),
            }
        };

        buf.clear();

        let nr = 'recv: loop {
            match session.try_read(&mut buf).expect("[Client] try_read") {
                wolfssl::Poll::PendingRead => io.wait_read("Client", "Read").await,
                wolfssl::Poll::PendingWrite => io.wait_write("Client", "Read").await,
                wolfssl::Poll::Ready(nr) => {
                    println!("[Client] Read {nr} complete!");
                    break 'recv nr;
                }
                wolfssl::Poll::AppData(_b) => todo!("[Client] Handle App Data"),
            }
        };
        let pong = String::from_utf8_lossy(&buf[..nr]);
        println!("[Client] Got pong: {pong}");
    }

    println!("[Client] Finished");
}

async fn server<S: SockIO>(sock: S, protocol: Protocol) {
    let sock = std::rc::Rc::new(sock);

    let ca_cert = RootCertificate::Asn1Buffer(CA_CERT);
    let cert = Secret::Asn1Buffer(SERVER_CERT);
    let key = Secret::Asn1Buffer(SERVER_KEY);

    let ctx = ContextBuilder::new(protocol)
        .expect("[Server] new ContextBuilder")
        .with_root_certificate(ca_cert)
        .expect("[Server] add root certificate")
        .with_certificate(cert)
        .expect("[Server] add certificate")
        .with_private_key(key)
        .expect("[Server] add private key")
        .build();

    let io = SockIOCallbacks(sock);
    let session_config = SessionConfig::new(io.clone()).with_dtls_nonblocking(true);
    let mut session = ctx
        .new_session(session_config)
        .expect("[Server] Create Server SSL session");

    println!("[Server] Connecting...");
    'negotiate: loop {
        match session.try_negotiate().expect("[Server] try_negotiate") {
            wolfssl::Poll::PendingRead => io.wait_read("Server", "Negotiate").await,
            wolfssl::Poll::PendingWrite => io.wait_write("Server", "Negotiate").await,
            wolfssl::Poll::Ready(_) => {
                println!("[Server] Negotiation complete!");
                break 'negotiate;
            }
            wolfssl::Poll::AppData(_b) => todo!("[Server] Handle App Data"),
        }
    }

    assert!(session.is_init_finished());

    let mut buf = BytesMut::with_capacity(1900);

    println!("[Server] Starting ping/pong loop");

    'pingpong: loop {
        buf.clear();
        let nr = 'recv: loop {
            match session.try_read(&mut buf).expect("[Server] try_read") {
                wolfssl::Poll::PendingRead => io.wait_read("Server", "Read").await,
                wolfssl::Poll::PendingWrite => io.wait_write("Server", "Read").await,
                wolfssl::Poll::Ready(nr) => {
                    println!("[Server] Read {nr} complete!");
                    break 'recv nr;
                }
                wolfssl::Poll::AppData(_b) => todo!("[Server] Handle App Data"),
            }
        };
        let ping = String::from_utf8_lossy(&buf[..nr]);
        println!("[Server] Got ping: {ping}");

        // We don't reuse buf since we don't want to mess with truncate and reexpand.

        let mut pong: BytesMut = ping.as_ref().into();
        let _nr = 'send: loop {
            match session.try_write(&mut pong).expect("[Server] try_write") {
                wolfssl::Poll::PendingRead => io.wait_read("Server", "Write").await,
                wolfssl::Poll::PendingWrite => io.wait_write("Server", "Write").await,
                wolfssl::Poll::Ready(nr) => {
                    println!("[Server] Write {nr} complete!");
                    break 'send nr;
                }
                wolfssl::Poll::AppData(_b) => todo!("[Server] Handle App Data"),
            }
        };

        if ping == "QUIT" {
            break 'pingpong;
        }
    }

    println!("[Server] Finished");
}

#[tokio::test]
async fn dtls() {
    use Protocol::*;

    #[cfg(feature = "debug")]
    wolfssl::enable_debugging(true);

    // Communicate over a local datagram socket for simplicity
    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");

    let client = client(client_sock, DtlsClientV1_2);
    let server = server(server_sock, DtlsServerV1_2);

    // Note that this runs concurrently but not in parallel
    tokio::join!(client, server);
}

#[tokio::test]
async fn tls() {
    use Protocol::*;

    #[cfg(feature = "debug")]
    wolfssl::enable_debugging(true);

    // Communicate over a local stream socket for simplicity
    let (client_sock, server_sock) = UnixStream::pair().expect("UnixStream");

    let client = client(client_sock, TlsClientV1_3);
    let server = server(server_sock, TlsServerV1_3);

    // Note that this runs concurrently but not in parallel
    tokio::join!(client, server);
}
