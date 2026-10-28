//! Forward wolfSSL's actual build mode, published by wolfssl-sys, as the
//! `wolfssl_single_threaded` cfg.

fn main() {
    let single_threaded =
        std::env::var("DEP_WOLFSSL_SINGLE_THREADED").is_ok_and(|mode| mode == "1");

    println!("cargo:rustc-check-cfg=cfg(wolfssl_single_threaded)");
    if single_threaded {
        println!("cargo:rustc-cfg=wolfssl_single_threaded");
    }

    println!("cargo:rerun-if-changed=build.rs");
}
