//! Test sending ping/pong messages back and forth

#![deny(unsafe_code)] // unsafety should all be in the library.

#[cfg(feature = "debug")]
use wolfssl::Tls13SecretCallbacks;
use wolfssl::{
    ContextBuilder, IOCallbacks, Method, ProtocolVersion, RootCertificate, Secret, SessionConfig,
};

use async_trait::async_trait;
use bytes::BytesMut;
use test_case::test_case;
use tokio::net::{UnixDatagram, UnixStream};

const CA_CERT_2048: &[u8] = &include!("data/ca_cert_der_2048");
const SERVER_CERT_2048: &[u8] = &include!("data/server_cert_der_2048");
const SERVER_KEY_2048: &[u8] = &include!("data/server_key_der_2048");
const CA_CERT_4096: &[u8] = &include!("data/ca_cert_der_4096");
const SERVER_CERT_4096: &[u8] = &include!("data/server_cert_der_4096");
const SERVER_KEY_4096: &[u8] = &include!("data/server_key_der_4096");

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
    async fn poll(&self, interest: tokio::io::Interest) {
        let _ = self.0.ready(interest).await.unwrap();
    }
}

macro_rules! retry_io {
    { $iocb:expr, $f:expr } => {
        loop {
            match $f {
                Ok(wolfssl::Poll::PendingRead) => $iocb.poll(tokio::io::Interest::READABLE).await,
                Ok(wolfssl::Poll::PendingWrite) => $iocb.poll(tokio::io::Interest::WRITABLE).await,
                Ok(wolfssl::Poll::Ready(ok)) => break Ok(ok),
                Ok(wolfssl::Poll::AppData(_)) => panic!("Unexpected/Unhandled AppData"),
                Err(err) => break Err(err),
            };
        }
    }
}

impl<IOCB: SockIO> IOCallbacks for SockIOCallbacks<IOCB> {
    fn recv(&mut self, buf: &mut [u8]) -> wolfssl::IOCallbackResult<usize> {
        match self.0.try_recv(buf) {
            Ok(nr) => wolfssl::IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                wolfssl::IOCallbackResult::WouldBlock
            }
            Err(err) => wolfssl::IOCallbackResult::Err(err),
        }
    }

    fn send(&mut self, buf: &[u8]) -> wolfssl::IOCallbackResult<usize> {
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

#[cfg(feature = "debug")]
struct KeyLogger;

#[cfg(feature = "debug")]
impl Tls13SecretCallbacks for KeyLogger {
    fn wireshark_keylog(&self, secret: String) {
        eprintln!("{}", secret);
    }
}

async fn client<S: SockIO>(
    sock: S,
    method: Method,
    exp_protocol_version: ProtocolVersion,
    suite_key_size: &TestSuiteKeySize,
) {
    let sock = std::rc::Rc::new(sock);

    let ca_cert = RootCertificate::Asn1Buffer(match suite_key_size {
        TestSuiteKeySize::Bits2048 => CA_CERT_2048,
        TestSuiteKeySize::Bits4096 => CA_CERT_4096,
    });

    let ctx = ContextBuilder::new(method)
        .expect("[Client] new ContextBuilder")
        .with_root_certificate(ca_cert)
        .expect("[Client] add root certificate")
        .build();

    let io = SockIOCallbacks(sock);
    let session_config = SessionConfig::new(io.clone()).with_dtls_nonblocking(true);

    #[cfg(feature = "debug")]
    let session_config = session_config.with_key_logger(std::sync::Arc::new(KeyLogger));

    let mut session = ctx
        .new_session(session_config)
        .expect("[Client] Create Client SSL session");

    println!("[Client] Connecting...");
    retry_io! { io, session.try_negotiate() }.expect("[Client] try_negotiate");

    assert!(session.is_init_finished());

    let version = session.version();
    println!("[Client] with {:?}", version);
    assert_eq!(exp_protocol_version, version);

    println!("[Client] Starting ping/pong loop");

    let mut buf = BytesMut::with_capacity(1900);

    for ping in ["Hello", /*"Goodbye",*/ "QUIT"] {
        println!("[Client] Send {ping}");

        let mut ping: BytesMut = ping.into();
        let _nr = retry_io! { io, session.try_write(&mut ping) }.expect("[Client] try_write");

        buf.clear();

        let nr = retry_io! { io,  session.try_read(&mut buf) }.expect("[Client] try_read");
        let pong = String::from_utf8_lossy(&buf[..nr]);
        println!("[Client] Got pong: {pong}");
    }

    println!("[Client] Finished");
}

async fn server<S: SockIO>(
    sock: S,
    method: Method,
    exp_protocol_version: ProtocolVersion,
    suite_key_size: &TestSuiteKeySize,
) {
    let sock = std::rc::Rc::new(sock);

    let ca_cert = RootCertificate::Asn1Buffer(match suite_key_size {
        TestSuiteKeySize::Bits2048 => CA_CERT_2048,
        TestSuiteKeySize::Bits4096 => CA_CERT_4096,
    });
    let cert = Secret::Asn1Buffer(match suite_key_size {
        TestSuiteKeySize::Bits2048 => SERVER_CERT_2048,
        TestSuiteKeySize::Bits4096 => SERVER_CERT_4096,
    });
    let key = Secret::Asn1Buffer(match suite_key_size {
        TestSuiteKeySize::Bits2048 => SERVER_KEY_2048,
        TestSuiteKeySize::Bits4096 => SERVER_KEY_4096,
    });

    let ctx = ContextBuilder::new(method)
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
    retry_io! { io, session.try_negotiate() }.expect("[Server] try_negotiate");

    assert!(session.is_init_finished());

    let version = session.version();
    println!("[Server] connected with {:?}", version);
    assert_eq!(exp_protocol_version, version);

    let mut buf = BytesMut::with_capacity(1900);

    println!("[Server] Starting ping/pong loop");

    loop {
        buf.clear();
        let nr = retry_io! { io, session.try_read(&mut buf) }.expect("[Server] try_read");
        let ping = String::from_utf8_lossy(&buf[..nr]);
        println!("[Server] Got ping: {ping}");

        // We don't reuse buf since we don't want to mess with truncate and reexpand.

        let mut pong: BytesMut = ping.as_ref().into();
        let _nr = retry_io! { io, session.try_write(&mut pong) }.expect("[Server] try_write");

        if ping == "QUIT" {
            break;
        }
    }

    println!("[Server] Finished");
}

enum TestSuiteKeySize {
    Bits2048,
    Bits4096,
}

// TODO: WolfSSL downgrade bug
// #[test_case(Method::DtlsClient, Method::DtlsServerV1_2; "client_server_1.2")]
#[test_case(Method::DtlsClientV1_2, Method::DtlsServerV1_3, ProtocolVersion::Unknown, &TestSuiteKeySize::Bits2048 => panics "record layer version error"; "client_1.2_server_1.3_2048_bits")]
#[test_case(Method::DtlsClientV1_2, Method::DtlsServerV1_2, ProtocolVersion::DtlsV1_2, &TestSuiteKeySize::Bits2048; "client_1.2_server_1.2_2048_bits")]
#[test_case(Method::DtlsClientV1_2, Method::DtlsServer, ProtocolVersion::DtlsV1_2, &TestSuiteKeySize::Bits2048; "client_1.2_server_any_2048_bits")]
#[test_case(Method::DtlsClientV1_3, Method::DtlsServerV1_3, ProtocolVersion::DtlsV1_3, &TestSuiteKeySize::Bits2048; "client_1.3_server_1.3_2048_bits")]
#[test_case(Method::DtlsClientV1_3, Method::DtlsServerV1_2, ProtocolVersion::Unknown, &TestSuiteKeySize::Bits2048 => panics "record layer version error"; "client_1.3_server_1.2_2048_bits")]
#[test_case(Method::DtlsClientV1_3, Method::DtlsServer, ProtocolVersion::DtlsV1_3, &TestSuiteKeySize::Bits2048; "client_any_1.3_server_any_2048_bits")]
#[test_case(Method::DtlsClient, Method::DtlsServerV1_3, ProtocolVersion::DtlsV1_3, &TestSuiteKeySize::Bits2048; "client_any_server_1.3_2048_bits")]
#[test_case(Method::DtlsClient, Method::DtlsServer, ProtocolVersion::DtlsV1_3, &TestSuiteKeySize::Bits2048; "client_any_server_any_2048_bits")]
#[test_case(Method::DtlsClientV1_2, Method::DtlsServerV1_3, ProtocolVersion::Unknown, &TestSuiteKeySize::Bits4096 => panics "record layer version error"; "client_1.2_server_1.3_4096_bits")]
#[test_case(Method::DtlsClientV1_2, Method::DtlsServerV1_2, ProtocolVersion::DtlsV1_2, &TestSuiteKeySize::Bits4096; "client_1.2_server_1.2_4096_bits")]
#[test_case(Method::DtlsClientV1_2, Method::DtlsServer, ProtocolVersion::DtlsV1_2, &TestSuiteKeySize::Bits4096; "client_1.2_server_any_4096_bits")]
#[test_case(Method::DtlsClientV1_3, Method::DtlsServerV1_3, ProtocolVersion::DtlsV1_3, &TestSuiteKeySize::Bits4096; "client_1.3_server_1.3_4096_bits")]
#[test_case(Method::DtlsClientV1_3, Method::DtlsServerV1_2, ProtocolVersion::Unknown, &TestSuiteKeySize::Bits4096 => panics "record layer version error"; "client_1.3_server_1.2_4096_bits")]
#[test_case(Method::DtlsClientV1_3, Method::DtlsServer, ProtocolVersion::DtlsV1_3, &TestSuiteKeySize::Bits4096; "client_any_1.3_server_any_4096_bits")]
#[test_case(Method::DtlsClient, Method::DtlsServerV1_3, ProtocolVersion::DtlsV1_3, &TestSuiteKeySize::Bits4096; "client_any_server_1.3_4096_bits")]
#[test_case(Method::DtlsClient, Method::DtlsServer, ProtocolVersion::DtlsV1_3, &TestSuiteKeySize::Bits4096; "client_any_server_any_4096_bits")]
#[tokio::test]
async fn dtls(
    client_method: Method,
    server_method: Method,
    exp_protocol_version: ProtocolVersion,
    suite_key_size: &TestSuiteKeySize,
) {
    #[cfg(feature = "debug")]
    wolfssl::enable_debugging(true);

    // Communicate over a local datagram socket for simplicity
    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");

    let client = client(
        client_sock,
        client_method,
        exp_protocol_version,
        suite_key_size,
    );
    let server = server(
        server_sock,
        server_method,
        exp_protocol_version,
        suite_key_size,
    );

    // Note that this runs concurrently but not in parallel
    tokio::join!(client, server);
}

#[test_case(Method::TlsClientV1_2, Method::TlsServerV1_3, ProtocolVersion::Unknown, &TestSuiteKeySize::Bits2048 => panics "record layer version error"; "client_1.2_server_1.3_2048_bits")]
#[test_case(Method::TlsClientV1_2, Method::TlsServerV1_2, ProtocolVersion::TlsV1_2, &TestSuiteKeySize::Bits2048; "client_1.2_server_1.2")]
#[test_case(Method::TlsClientV1_2, Method::TlsServer, ProtocolVersion::TlsV1_2, &TestSuiteKeySize::Bits2048; "client_1.2_server_any_2048_bits")]
#[test_case(Method::TlsClientV1_3, Method::TlsServerV1_3, ProtocolVersion::TlsV1_3, &TestSuiteKeySize::Bits2048; "client_1.3_server_1.3_2048_bits")]
#[test_case(Method::TlsClientV1_3, Method::TlsServerV1_2, ProtocolVersion::Unknown, &TestSuiteKeySize::Bits2048 => panics "malformed buffer input error"; "client_1.3_server_1.2_2048_bits")]
#[test_case(Method::TlsClientV1_3, Method::TlsServer, ProtocolVersion::TlsV1_3, &TestSuiteKeySize::Bits2048; "client_1.3_server_any_2048_bits")]
#[test_case(Method::TlsClient, Method::TlsServerV1_3, ProtocolVersion::TlsV1_3, &TestSuiteKeySize::Bits2048; "client_any_server_1.3_2048_bits")]
#[test_case(Method::TlsClient, Method::TlsServerV1_2, ProtocolVersion::TlsV1_2, &TestSuiteKeySize::Bits2048; "client_any_server_1.2_2048_bits")]
#[test_case(Method::TlsClient, Method::TlsServer, ProtocolVersion::TlsV1_3, &TestSuiteKeySize::Bits2048; "client_any_server_any_2048_bits")]
#[test_case(Method::TlsClientV1_2, Method::TlsServerV1_3, ProtocolVersion::Unknown, &TestSuiteKeySize::Bits4096 => panics "record layer version error"; "client_1.2_server_1.3_4096_bits")]
#[test_case(Method::TlsClientV1_2, Method::TlsServerV1_2, ProtocolVersion::TlsV1_2, &TestSuiteKeySize::Bits4096; "client_1.2_server_1.2_4096_bits")]
#[test_case(Method::TlsClientV1_2, Method::TlsServer, ProtocolVersion::TlsV1_2, &TestSuiteKeySize::Bits4096; "client_1.2_server_any_4096_bits")]
#[test_case(Method::TlsClientV1_3, Method::TlsServerV1_3, ProtocolVersion::TlsV1_3, &TestSuiteKeySize::Bits4096; "client_1.3_server_1.3_4096_bits")]
#[test_case(Method::TlsClientV1_3, Method::TlsServerV1_2, ProtocolVersion::Unknown, &TestSuiteKeySize::Bits4096 => panics "malformed buffer input error"; "client_1.3_server_1.2_4096_bits")]
#[test_case(Method::TlsClientV1_3, Method::TlsServer, ProtocolVersion::TlsV1_3, &TestSuiteKeySize::Bits4096; "client_1.3_server_any_4096_bits")]
#[test_case(Method::TlsClient, Method::TlsServerV1_3, ProtocolVersion::TlsV1_3, &TestSuiteKeySize::Bits4096; "client_any_server_1.3_4096_bits")]
#[test_case(Method::TlsClient, Method::TlsServerV1_2, ProtocolVersion::TlsV1_2, &TestSuiteKeySize::Bits4096; "client_any_server_1.2_4096_bits")]
#[test_case(Method::TlsClient, Method::TlsServer, ProtocolVersion::TlsV1_3, &TestSuiteKeySize::Bits4096; "client_any_server_any_4096_bits")]
#[tokio::test]
async fn tls(
    client_method: Method,
    server_method: Method,
    exp_protocol_version: ProtocolVersion,
    suite_key_size: &TestSuiteKeySize,
) {
    #[cfg(feature = "debug")]
    wolfssl::enable_debugging(true);

    // Communicate over a local stream socket for simplicity
    let (client_sock, server_sock) = UnixStream::pair().expect("UnixStream");

    let client = client(
        client_sock,
        client_method,
        exp_protocol_version,
        suite_key_size,
    );
    let server = server(
        server_sock,
        server_method,
        exp_protocol_version,
        suite_key_size,
    );

    // Note that this runs concurrently but not in parallel
    tokio::join!(client, server);
}
