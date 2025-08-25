#![cfg(feature = "debug")]

use std::fmt::{self, Display};
#[allow(unused_imports)] // Needed for windows
use std::os::raw::{c_int, c_uint};
use std::sync::Arc;

/// Application provided callbacks to receive TLS1.3 secrets
///
/// There are two apis in this trait.
/// Application can opt to receive either raw secrets or String which is suitable to use in
/// WireShark keylog
/// <https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html#ChIOExportTLSSessionKeys>
/// <https://wiki.wireshark.org/TLS#using-the-pre-master-secret>
pub trait Tls13SecretCallbacks {
    /// Called when WolfSSL wishes to send new TLS1.3 secret used
    /// `secret` is formatted as WireShark keylog string.
    /// It can be saved to a file and used in WireShark directly
    fn wireshark_keylog(&self, _secret: String);

    /// Called when WolfSSL wishes to send new TLS1.3 secret used
    /// Random value and secrets along with secret type is send separately
    /// The default implementation parses the secret/random and generate the
    /// WireShark compatible keylog string and call `Tls13SecretCallbacks::wireshark_keylog`.
    ///
    /// Application can choose to override this to get the secret/random directly.
    fn secrets(&self, secret_type: Tls13Secret, random: &[u8], secret: &[u8]) {
        let mut keylog = secret_type.to_string();
        keylog.push(' ');

        random
            .iter()
            .for_each(|i| keylog.push_str(&format!("{i:02x}")));
        keylog.push(' ');

        secret
            .iter()
            .for_each(|f| keylog.push_str(&format!("{f:02x}")));
        keylog.push('\n');

        self.wireshark_keylog(keylog);
    }
}

/// Convenience type to use as function arguments
pub type Tls13SecretCallbacksArg = Arc<dyn Tls13SecretCallbacks + Send + Sync>;

pub(crate) const RANDOM_SIZE: usize = 32;

#[cfg(not(windows))]
/// Tls13 Secret type from ffi
pub type Tls13SecretType = c_uint;

#[cfg(windows)]
/// Tls13 Secret type from ffi
pub type Tls13SecretType = c_int;

/// Tls13 Secret types
/// To be used in Wireshark
pub enum Tls13Secret {
    /// "CLIENT_EARLY_TRAFFIC_SECRET"
    ClientEarlyTrafficSecret,
    /// "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
    ClientHandshakeTrafficSecret,
    /// "SERVER_HANDSHAKE_TRAFFIC_SECRET"
    ServerHandshakeTrafficSecret,
    /// "CLIENT_TRAFFIC_SECRET_0"
    ClientTrafficSecret,
    ///"SERVER_TRAFFIC_SECRET_0"
    ServerTrafficSecret,
    /// "EARLY_EXPORTER_SECRET"
    EarlyExporterSecret,
    /// "EXPORTER_SECRET"
    ExporterSecret,
    /// "UNKNOWN_SECRET"
    UnknownSecret(Tls13SecretType),
}

impl Display for Tls13Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Tls13Secret::*;
        let secret = match self {
            ClientEarlyTrafficSecret => "CLIENT_EARLY_TRAFFIC_SECRET",
            ClientHandshakeTrafficSecret => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            ServerHandshakeTrafficSecret => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            ClientTrafficSecret => "CLIENT_TRAFFIC_SECRET_0",
            ServerTrafficSecret => "SERVER_TRAFFIC_SECRET_0",
            EarlyExporterSecret => "EARLY_EXPORTER_SECRET",
            ExporterSecret => "EXPORTER_SECRET",
            UnknownSecret(_e) => "UNKNOWN_SECRET",
        };
        write!(f, "{secret}")
    }
}

impl From<c_int> for Tls13Secret {
    fn from(value: c_int) -> Self {
        match value as Tls13SecretType {
            wolfssl_sys::Tls13Secret_CLIENT_EARLY_TRAFFIC_SECRET => {
                Tls13Secret::ClientEarlyTrafficSecret
            }
            wolfssl_sys::Tls13Secret_CLIENT_HANDSHAKE_TRAFFIC_SECRET => {
                Tls13Secret::ClientHandshakeTrafficSecret
            }
            wolfssl_sys::Tls13Secret_SERVER_HANDSHAKE_TRAFFIC_SECRET => {
                Tls13Secret::ServerHandshakeTrafficSecret
            }
            wolfssl_sys::Tls13Secret_CLIENT_TRAFFIC_SECRET => Tls13Secret::ClientTrafficSecret,
            wolfssl_sys::Tls13Secret_SERVER_TRAFFIC_SECRET => Tls13Secret::ServerTrafficSecret,
            wolfssl_sys::Tls13Secret_EARLY_EXPORTER_SECRET => Tls13Secret::EarlyExporterSecret,
            wolfssl_sys::Tls13Secret_EXPORTER_SECRET => Tls13Secret::ExporterSecret,
            e => Tls13Secret::UnknownSecret(e),
        }
    }
}
