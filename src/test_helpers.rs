use once_cell::sync::OnceCell;

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
