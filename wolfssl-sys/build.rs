/*!
 * Contains the build process for WolfSSL
 */

extern crate bindgen;

use autotools::Config;
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use std::process::Command;

static WOLFSSL_VERSION: &str = "wolfssl-5.6.0-stable";

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
 * Extract WolfSSL
 */
fn extract_wolfssl(dest: &str) -> std::io::Result<()> {
    Command::new("tar")
        .arg("-zxvf")
        .arg(format!("vendor/{WOLFSSL_VERSION}.tar.gz"))
        .arg("-C")
        .arg(dest)
        .status()
        .unwrap();

    Ok(())
}

/**
Builds WolfSSL
*/
fn build_wolfssl(dest: &str) -> PathBuf {
    // Create the config
    let mut conf = Config::new(format!("{dest}/{WOLFSSL_VERSION}"));
    // Configure it
    conf.reconf("-ivf")
        // Only build the static library
        .enable_static()
        .disable_shared()
        // Enable TLS/1.3
        .enable("tls13", None)
        // Disable old TLS versions
        .disable("oldtls", None)
        // Enable single threaded mode
        .enable("singlethreaded", None)
        // Enable D/TLS
        .enable("dtls", None)
        // Enable single precision
        .enable("sp", None)
        // Enable single precision ASM
        .enable("sp-asm", None)
        // Enable setting the D/TLS MTU size
        .enable("dtls-mtu", None)
        // Disable SHA3
        .disable("sha3", None)
        // Disable DH key exchanges
        .disable("dh", None)
        // Enable elliptic curve exchanges
        .enable("supportedcurves", None)
        .enable("curve25519", None)
        // Enable Secure Renegotiation
        .enable("secure-renegotiation", None)
        // Enable SNI
        .enable("sni", None)
        // CFLAGS
        .cflag("-g")
        .cflag("-fPIC")
        .cflag("-DWOLFSSL_DTLS_ALLOW_FUTURE")
        .cflag("-DWOLFSSL_MIN_RSA_BITS=2048")
        .cflag("-DWOLFSSL_MIN_ECC_BITS=256");

    if cfg!(feature = "debug") {
        conf.enable("debug", None);
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
    let dst_string = env::var("OUT_DIR").unwrap();

    // Extract WolfSSL
    extract_wolfssl(&dst_string)?;

    // Configure and build WolfSSL
    let dst = build_wolfssl(&dst_string);

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
    let dst_include = format!("{dst_string}/include");

    // Build the Rust binding
    let builder = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{dst_include}/"))
        .parse_callbacks(Box::new(ignored_macros))
        .formatter(bindgen::Formatter::Rustfmt);

    let builder = builder
        .allowlist_file(format!("{dst_include}/wolfssl/.*.h"))
        .allowlist_file(format!("{dst_include}/wolfssl/wolfcrypt/.*.h"))
        .allowlist_file(format!("{dst_include}/wolfssl/openssl/compat_types.h"));

    let builder = builder.blocklist_function("wolfSSL_BIO_vprintf");

    let bindings: bindgen::Bindings = builder.generate().expect("Unable to generate bindings");

    // Write out the bindings
    bindings
        .write_to_file(dst.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Tell cargo to tell rustc to link in WolfSSL
    println!("cargo:rustc-link-lib=static=wolfssl");

    if cfg!(feature = "postquantum") {
        println!("cargo:rustc-link-lib=static=oqs");
    }

    println!("cargo:rustc-link-search=native={}/lib/", dst_string);

    println!("cargo:include={}", dst_string);

    // Invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // That should do it...
    Ok(())
}
