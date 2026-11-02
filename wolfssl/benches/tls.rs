//! Criterion benchmarks of TLS 1.3 and DTLS 1.3 sessions.
//!
//! Client and server sessions are connected in memory, so these measure
//! wolfSSL alone: a full handshake for each key exchange group, and record
//! encryption plus decryption for each cipher suite.
//!
//! `cargo bench -p wolfssl --bench tls [-- <filter>]`

use bytes::BytesMut;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};
use wolfssl::{
    Context, ContextBuilder, CurveGroup, IOCallbackResult, IOCallbacks, Method, Poll,
    RootCertificate, Secret, Session, SessionConfig,
};

const CA_CERT: &[u8] = &include!("../tests/data/ca_cert_der_2048");
const SERVER_CERT: &[u8] = &include!("../tests/data/server_cert_der_2048");
const SERVER_KEY: &[u8] = &include!("../tests/data/server_key_der_2048");

/// Small packet and a full-size packet at a typical MTU
const SIZES: [usize; 2] = [64, 1350];

/// (name, group, name wolfSSL reports for it)
const GROUPS: [(&str, CurveGroup, &str); 4] = [
    (
        "p521_mlkem1024",
        CurveGroup::P521MLKEM1024,
        "SecP521r1MLKEM1024",
    ),
    (
        "x25519_mlkem768",
        CurveGroup::X25519MLKEM768,
        "X25519MLKEM768",
    ),
    ("secp256r1", CurveGroup::EccSecp256R1, "SECP256R1"),
    ("x25519", CurveGroup::EccX25519, "X25519"),
];

#[derive(Clone, Copy)]
enum Transport {
    Tls,
    Dtls,
}

impl Transport {
    fn name(self) -> &'static str {
        match self {
            Transport::Tls => "tls",
            Transport::Dtls => "dtls",
        }
    }

    fn methods(self) -> (Method, Method) {
        match self {
            Transport::Tls => (Method::TlsClientV1_3, Method::TlsServerV1_3),
            Transport::Dtls => (Method::DtlsClientV1_3, Method::DtlsServerV1_3),
        }
    }
}

#[derive(Clone, Copy)]
enum Cipher {
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Cipher {
    fn name(self) -> &'static str {
        match self {
            Cipher::Aes256Gcm => "aes256_gcm",
            Cipher::Chacha20Poly1305 => "chacha20_poly1305",
        }
    }

    /// Name for `with_cipher_list`
    fn cipher_list(self) -> &'static str {
        match self {
            Cipher::Aes256Gcm => "TLS13-AES256-GCM-SHA384",
            Cipher::Chacha20Poly1305 => "TLS13-CHACHA20-POLY1305-SHA256",
        }
    }

    /// Name wolfSSL reports once negotiated
    fn suite(self) -> &'static str {
        match self {
            Cipher::Aes256Gcm => "TLS_AES_256_GCM_SHA384",
            Cipher::Chacha20Poly1305 => "TLS_CHACHA20_POLY1305_SHA256",
        }
    }
}

/// One end of an in-memory link. Datagrams keep their boundaries; a stream
/// is read as bytes.
struct Link {
    transport: Transport,
    tx: Rc<RefCell<VecDeque<Vec<u8>>>>,
    rx: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

impl Link {
    fn pair(transport: Transport) -> (Self, Self) {
        let a = Rc::new(RefCell::new(VecDeque::new()));
        let b = Rc::new(RefCell::new(VecDeque::new()));
        (
            Self {
                transport,
                tx: a.clone(),
                rx: b.clone(),
            },
            Self {
                transport,
                tx: b,
                rx: a,
            },
        )
    }
}

impl IOCallbacks for Link {
    fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult<usize> {
        let mut rx = self.rx.borrow_mut();
        let Some(front) = rx.front_mut() else {
            return IOCallbackResult::WouldBlock;
        };
        let n = front.len().min(buf.len());
        buf[..n].copy_from_slice(&front[..n]);
        match self.transport {
            Transport::Dtls => {
                rx.pop_front();
            }
            Transport::Tls => {
                front.drain(..n);
                if front.is_empty() {
                    rx.pop_front();
                }
            }
        }
        IOCallbackResult::Ok(n)
    }

    fn send(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
        self.tx.borrow_mut().push_back(buf.to_vec());
        IOCallbackResult::Ok(buf.len())
    }
}

struct Setup {
    transport: Transport,
    cipher: Cipher,
    group: CurveGroup,
    client: Context,
    server: Context,
}

impl Setup {
    fn new(transport: Transport, cipher: Cipher, group: CurveGroup) -> Self {
        let (client_method, server_method) = transport.methods();
        let client = ContextBuilder::new(client_method)
            .unwrap()
            .with_root_certificate(RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap()
            .with_cipher_list(cipher.cipher_list())
            .unwrap()
            .build();
        let server = ContextBuilder::new(server_method)
            .unwrap()
            .with_private_key(Secret::Asn1Buffer(SERVER_KEY))
            .unwrap()
            .with_certificate(Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_groups(&[group])
            .unwrap()
            .with_cipher_list(cipher.cipher_list())
            .unwrap()
            .build();
        Self {
            transport,
            cipher,
            group,
            client,
            server,
        }
    }

    /// Create client and server sessions and complete the handshake
    fn connect(&self) -> (Session<Link>, Session<Link>) {
        let (client_link, server_link) = Link::pair(self.transport);
        let dtls = matches!(self.transport, Transport::Dtls);

        let mut client = self
            .client
            .new_session(
                SessionConfig::new(client_link)
                    .when(dtls, |s| s.with_dtls_nonblocking(true))
                    .with_keyshare_group(self.group),
            )
            .unwrap();
        let mut server = self
            .server
            .new_session(SessionConfig::new(server_link).when(dtls, |s| {
                // Post-quantum key shares make the ClientHello span several datagrams
                s.with_dtls_nonblocking(true)
                    .with_dtls13_allow_ch_frag(true)
            }))
            .unwrap();

        for _ in 0..100 {
            let client_done = matches!(client.try_negotiate().unwrap(), Poll::Ready(_));
            let server_done = matches!(server.try_negotiate().unwrap(), Poll::Ready(_));
            if client_done && server_done {
                // Process anything still in flight, such as DTLS 1.3 ACKs
                let mut buf = [0u8; 16];
                assert!(matches!(
                    client.try_read_slice(&mut buf),
                    Ok(Poll::PendingRead)
                ));
                return (client, server);
            }
        }
        panic!("handshake did not complete");
    }

    /// Fail rather than benchmark something else if negotiation changes
    fn check(&self, curve: &str) {
        let (mut client, _) = self.connect();
        assert_eq!(
            client.get_current_cipher_name().as_deref(),
            Some(self.cipher.suite())
        );
        assert_eq!(client.get_current_curve_name().as_deref(), Some(curve));
    }
}

fn handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    for transport in [Transport::Tls, Transport::Dtls] {
        for (name, curve_group, curve) in GROUPS {
            let setup = Setup::new(transport, Cipher::Aes256Gcm, curve_group);
            setup.check(curve);
            group.bench_function(format!("{}/{name}", transport.name()), |b| {
                b.iter(|| setup.connect())
            });
        }
    }
    group.finish();
}

fn record(c: &mut Criterion) {
    let mut group = c.benchmark_group("record");
    for transport in [Transport::Tls, Transport::Dtls] {
        for cipher in [Cipher::Aes256Gcm, Cipher::Chacha20Poly1305] {
            let setup = Setup::new(transport, cipher, CurveGroup::EccX25519);
            setup.check("X25519");
            let (mut client, mut server) = setup.connect();
            let mut buf = BytesMut::zeroed(2048);

            for size in SIZES {
                let data = vec![0xa5; size];
                group.throughput(Throughput::Bytes(size as u64));
                let id = BenchmarkId::new(format!("{}/{}", transport.name(), cipher.name()), size);
                // Encrypt on the client and decrypt on the server
                group.bench_function(id, |b| {
                    b.iter(|| {
                        assert!(matches!(client.try_write_slice(&data), Ok(Poll::Ready(n)) if n == size));
                        assert!(matches!(server.try_read_slice(&mut buf), Ok(Poll::Ready(n)) if n == size));
                    })
                });
            }
        }
    }
    group.finish();
}

criterion_group!(benches, handshake, record);
criterion_main!(benches);
