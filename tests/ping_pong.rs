use wolfssl::{ContextBuilder, Protocol, RootCertificate, Secret, Session, SessionConfig};

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

async fn run_io_loop<S: SockIO>(sock: &S, who: &'static str, sess: &mut Session) {
    let wr_buf = sess.io_write_out();

    let interest = if wr_buf.is_empty() {
        println!("[{who}] Polling for READ");
        tokio::io::Interest::READABLE
    } else {
        println!("[{who}] Polling for READ|WRITE");
        tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE
    };

    let readiness = sock
        .ready(interest)
        .await
        .unwrap_or_else(|_| panic!("[{who}] Poll for readiness"));

    println!("[{who}] Socket is ready for {readiness:?}");
    if readiness.is_readable() {
        let mut rd_buf = BytesMut::zeroed(1900); // TODO: less allocating all the time...
        match sock.try_recv(&mut rd_buf[..]) {
            Ok(nr) => {
                println!(
                    "[{who}] Received {nr} bytes into {} byte buffer",
                    rd_buf.len()
                );
                rd_buf.truncate(nr);
                sess.io_read_in(rd_buf.into());
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                println!("[{who}] Receive would block!");
                // ignored
            }
            Err(_err) => todo!("[{who}] recv error handling"),
        }
    }
    if readiness.is_writable() {
        // wr_buf should be non-empty per checks above...
        match sock.try_send(&wr_buf[..]) {
            Ok(nr) => {
                println!("[{who}] Sent {nr} bytes from {} byte buffer", wr_buf.len());
                assert!(nr == wr_buf.len(), "cannot handle partial write");
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                todo!("[{who}] Send would block, need to deal with content of wr_bufm not lose it");
            }
            Err(err) => todo!("[{who}] send error handling: {err}"),
        }
    }
}

async fn client<S: SockIO>(sock: S, protocol: Protocol) {
    let ca_cert = RootCertificate::Asn1Buffer(CA_CERT);

    let ctx = ContextBuilder::new(protocol)
        .expect("[Client] new ContextBuilder")
        .with_root_certificate(ca_cert)
        .expect("[Client] add root certificate")
        .build();

    let session_config = SessionConfig::new().with_dtls_nonblocking(true);
    let mut session = ctx
        .new_session(session_config)
        .expect("[Client] Create Client SSL session");

    println!("[Client] Connecting...");
    'negotiate: loop {
        match session.try_negotiate().expect("[Client] try_negotiate") {
            wolfssl::Poll::Pending => {
                println!("[Client] Negotiation pending, polling sock");
                run_io_loop(&sock, "Client", &mut session).await;
                println!("[Client] Poll complete");
            }
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
                wolfssl::Poll::Pending => {
                    println!("[Client] Write pending, polling sock");
                    run_io_loop(&sock, "Client", &mut session).await;
                    println!("[Client] Poll complete");
                }
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
                wolfssl::Poll::Pending => {
                    println!("[Client] Read pending, polling sock");
                    run_io_loop(&sock, "Client", &mut session).await;
                    println!("[Client] Poll complete");
                }
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

    let session_config = SessionConfig::new().with_dtls_nonblocking(true);
    let mut session = ctx
        .new_session(session_config)
        .expect("[Server] Create Server SSL session");

    println!("[Server] Connecting...");
    'negotiate: loop {
        match session.try_negotiate().expect("[Server] try_negotiate") {
            wolfssl::Poll::Pending => {
                println!("[Server] Negotiation pending, polling sock");
                run_io_loop(&sock, "Server", &mut session).await;
                println!("[Server] Poll complete");
            }
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
                wolfssl::Poll::Pending => {
                    println!("[Server] Read pending, polling sock");
                    run_io_loop(&sock, "Server", &mut session).await;
                    println!("[Server] Poll complete");
                }
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
                wolfssl::Poll::Pending => {
                    println!("[Server] Write pending, polling sock");
                    run_io_loop(&sock, "Server", &mut session).await;
                    println!("[Server] Poll complete");
                }
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
    // After we finish `session.callback_write_buffer` contains the
    // server's final message to the client, but nothing ever triggers
    // consuming (i.e. actually sending) that because we've told
    // WolfSSL we've taken it.
    //
    // Run a spurious I/O loop. The correct fix is to not tell WolfSSL
    // we've sent something we haven't in our callbacks.
    run_io_loop(&sock, "Server(EXTRA)", &mut session).await;
}

#[tokio::test]
async fn dtls() {
    use Protocol::*;

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

    // Communicate over a local stream socket for simplicity
    let (client_sock, server_sock) = UnixStream::pair().expect("UnixStream");

    let client = client(client_sock, TlsClientV1_3);
    let server = server(server_sock, TlsServerV1_3);

    // Note that this runs concurrently but not in parallel
    tokio::join!(client, server);
}
