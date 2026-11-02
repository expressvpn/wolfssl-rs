//! Runs wolfCrypt's own benchmark suite.
//!
//! `cargo bench -p wolfssl-sys --features benchmark -- [benchmark options]`,
//! e.g. `-- -aes-gcm -chacha20-poly1305` or `-- -?` for the full list.

use std::ffi::{c_char, c_int, CString};

extern "C" {
    fn wolfcrypt_benchmark_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
}

fn main() {
    // `cargo bench` passes `--bench`, which wolfCrypt does not understand
    let args: Vec<CString> = std::env::args()
        .filter(|a| a != "--bench")
        .map(|a| CString::new(a).unwrap())
        .collect();
    let mut argv: Vec<*mut c_char> = args.iter().map(|a| a.as_ptr() as *mut c_char).collect();
    argv.push(std::ptr::null_mut());

    // Ensure libwolfssl is linked in
    let _ = wolfssl_sys::wolfSSL_Init;

    let ret = unsafe { wolfcrypt_benchmark_main(args.len() as c_int, argv.as_mut_ptr()) };
    std::process::exit(ret);
}
