use crate::async_client::WolfClient;
use crate::WolfContextBuilder;
use once_cell::sync::OnceCell;
use tokio::io::{duplex, DuplexStream};

pub static INIT_ENV_LOGGER: OnceCell<()> = OnceCell::new();

pub const SERVER_CERT: &[u8] = &include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/test_data/server_cert_der_2048"
));

pub const SERVER_KEY: &[u8] = &include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/test_data/server_key_der_2048"
));

pub const CA_CERT: &[u8] = &include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/test_data/ca_cert_der_2048"
));

pub async fn make_connected_clients(
    client_builder: WolfContextBuilder,
    server_builder: WolfContextBuilder,
) -> (WolfClient<DuplexStream>, WolfClient<DuplexStream>) {
    let client_builder = client_builder
        .with_root_certificate(crate::RootCertificate::Asn1Buffer(CA_CERT))
        .unwrap();

    let server_builder = server_builder
        .with_certificate(crate::Secret::Asn1Buffer(SERVER_CERT))
        .unwrap()
        .with_private_key(crate::Secret::Asn1Buffer(SERVER_KEY))
        .unwrap();

    let (client_conn, server_conn) = duplex(usize::MAX);

    let client = async move {
        let mut client =
            WolfClient::new_with_context_and_stream(client_builder, client_conn).unwrap();
        client.negotiate().await.unwrap();
        client
    };

    let server = async move {
        let mut server =
            WolfClient::new_with_context_and_stream(server_builder, server_conn).unwrap();
        server.negotiate().await.unwrap();
        server
    };

    let (client, server) = tokio::join!(client, server);

    assert!(client.ssl_session.is_init_finished());
    assert!(server.ssl_session.is_init_finished());

    (client, server)
}
