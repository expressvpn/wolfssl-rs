/*!
 * Contains the build process for WolfSSL
 */

extern crate bindgen;

use autotools::Config;
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

/**
 * Work around for bindgen creating duplicate values.
 */
#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

/**
 * Copy WolfSSL
 */
fn copy_wolfssl(dest: &str) -> std::io::Result<PathBuf> {
    println!("cargo:rerun-if-changed=wolfssl-src");
    Command::new("cp")
        .arg("-rf")
        .arg("wolfssl-src")
        .arg(dest)
        .status()
        .unwrap();

    Ok(Path::new(dest).join("wolfssl-src"))
}

const PATCH_DIR: &str = "patches";
const PATCHES: &[&str] = &[];

/**
 * Apply patch to wolfssl-src
 */
fn apply_patch(wolfssl_path: &Path, patch: &str) {
    let patch = format!("{}/{}", PATCH_DIR, patch);

    let patch_buffer = File::open(patch).unwrap();
    Command::new("patch")
        .arg("-d")
        .arg(wolfssl_path)
        .arg("-p1")
        .stdin(patch_buffer)
        .status()
        .unwrap();
}

/**
Builds WolfSSL
*/
fn build_wolfssl(wolfssl_src: &Path) -> PathBuf {
    // Create the config
    let mut conf = Config::new(wolfssl_src);
    // Configure it
    conf.reconf("-ivf")
        // Disable benchmarks
        .disable("benchmark", None)
        // Disable DH key exchanges
        .disable("dh", None)
        // Disable examples
        .disable("examples", None)
        // Disable old TLS versions
        .disable("oldtls", None)
        // Disable SHA3
        .disable("sha3", None)
        // Disable dynamic library
        .disable_shared()
        // Disable sys ca certificate store
        .disable("sys-ca-certs", None)
        // Enable AES bitsliced implementation (cache attack safe)
        .enable("aes-bitsliced", None)
        // Enable Curve25519
        .enable("curve25519", None)
        // Enable D/TLS
        .enable("dtls", None)
        // Enable DTLS/1.3
        .enable("dtls13", None)
        // Enable DTLS1.3 ClientHello fragmentation
        .enable("dtls-frag-ch", None)
        // Enable setting the D/TLS MTU size
        .enable("dtls-mtu", None)
        // Enable Secure Renegotiation
        .enable("secure-renegotiation", None)
        // Enable single threaded mode
        .enable("singlethreaded", None)
        // Enable SNI
        .enable("sni", None)
        // Enable single precision
        .enable("sp", None)
        // Enable single precision ASM
        .enable("sp-asm", None)
        // Only build the static library
        .enable_static()
        // Enable elliptic curve exchanges
        .enable("supportedcurves", None)
        // Enable TLS/1.3
        .enable("tls13", None)
        // CFLAGS
        .cflag("-g")
        .cflag("-fPIC")
        .cflag("-DWOLFSSL_DTLS_ALLOW_FUTURE")
        .cflag("-DWOLFSSL_MIN_RSA_BITS=2048")
        .cflag("-DWOLFSSL_MIN_ECC_BITS=256")
        .cflag("-DUSE_CERT_BUFFERS_4096")
        .cflag("-DUSE_CERT_BUFFERS_256")
        .cflag("-DWOLFSSL_NO_SPHINCS");

    if cfg!(feature = "debug") {
        conf.enable("debug", None);
        conf.cflag("-DHAVE_SECRET_CALLBACK");
    }

    if cfg!(feature = "postquantum") {
        // Post Quantum support is provided by liboqs
        if let Some(include) = std::env::var_os("DEP_OQS_ROOT") {
            let oqs_path = &include.into_string().unwrap();
            conf.cflag(format!("-I{oqs_path}/build/include/"));
            conf.ldflag(format!("-L{oqs_path}/build/lib/"));
            conf.with("liboqs", None);
        } else {
            panic!("Post Quantum requested but liboqs appears to be missing?");
        }
    }

    if build_target::target_arch().unwrap() == build_target::Arch::X86_64 {
        // Enable Intel ASM optmisations
        conf.enable("intelasm", None);
        // Enable AES hardware acceleration
        conf.enable("aesni", None);
    }

    if build_target::target_arch().unwrap() == build_target::Arch::AARCH64 {
        // Enable ARM ASM optimisations
        conf.enable("armasm", None);
    }

    if build_target::target_arch().unwrap() == build_target::Arch::ARM {
        // Enable ARM ASM optimisations
        conf.enable("armasm", None);
    }

    // Build and return the config
    conf.build()
}

fn main() -> std::io::Result<()> {
    // Get the build directory
    let out_dir = env::var("OUT_DIR").unwrap();

    // Extract WolfSSL
    let wolfssl_src = copy_wolfssl(&out_dir)?;

    // Apply patches
    PATCHES.iter().for_each(|&f| apply_patch(&wolfssl_src, f));
    println!("cargo:rerun-if-changed={}", PATCH_DIR);

    // Configure and build WolfSSL
    let wolfssl_install_dir = build_wolfssl(&wolfssl_src);

    // We want to block some macros as they are incorrectly creating duplicate values
    // https://github.com/rust-lang/rust-bindgen/issues/687
    // TODO: Reach out to tlspuffin and ask if we can incorporate this code and credit them
    let mut hash_ignored_macros = HashSet::new();
    for i in &[
        "IPPORT_RESERVED",
        "EVP_PKEY_DH",
        "BIO_CLOSE",
        "BIO_NOCLOSE",
        "CRYPTO_LOCK",
        "ASN1_STRFLGS_ESC_MSB",
        "SSL_MODE_RELEASE_BUFFERS",
        // Wolfssl 4.3.0
        "GEN_IPADD",
        "EVP_PKEY_RSA",
    ] {
        hash_ignored_macros.insert(i.to_string());
    }

    let ignored_macros = IgnoreMacros(hash_ignored_macros);
    let wolfssl_include_dir = wolfssl_install_dir.join("include");

    // Build the Rust binding
    let builder = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}/", wolfssl_include_dir.to_str().unwrap()))
        .parse_callbacks(Box::new(ignored_macros))
        .formatter(bindgen::Formatter::Rustfmt);

    let builder = builder
        .allowlist_file(wolfssl_include_dir.join("wolfssl/.*.h").to_str().unwrap())
        .allowlist_file(
            wolfssl_include_dir
                .join("wolfssl/wolfcrypt/.*.h")
                .to_str()
                .unwrap(),
        )
        .allowlist_file(
            wolfssl_include_dir
                .join("wolfssl/openssl/compat_types.h")
                .to_str()
                .unwrap(),
        );

    let builder = builder.blocklist_function("wolfSSL_BIO_vprintf");

    let bindings: bindgen::Bindings = builder.generate().expect("Unable to generate bindings");

    // Write out the bindings
    bindings
        .write_to_file(wolfssl_install_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Tell cargo to tell rustc to link in WolfSSL
    println!("cargo:rustc-link-lib=static=wolfssl");

    if cfg!(feature = "postquantum") {
        println!("cargo:rustc-link-lib=static=oqs");
    }

    println!("cargo:rustc-link-search=native={}/lib/", out_dir);

    println!("cargo:include={}", out_dir);

    // Invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // That should do it...
    Ok(())
}
