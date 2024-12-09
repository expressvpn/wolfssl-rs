#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::useless_transmute)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::unnecessary_operation)]
#![allow(clippy::identity_op)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::ptr_offset_with_cast)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::os::raw::c_int;

pub const WOLFSSL_SUCCESS_c_int: c_int = WOLFSSL_SUCCESS as c_int;
pub const WOLFSSL_FAILURE_c_int: c_int = WOLFSSL_FAILURE as c_int;
pub const WOLFSSL_ERROR_WANT_READ_c_int: c_int = WOLFSSL_ERROR_WANT_READ as c_int;
pub const WOLFSSL_ERROR_WANT_WRITE_c_int: c_int = WOLFSSL_ERROR_WANT_WRITE as c_int;
pub const WOLFSSL_SHUTDOWN_NOT_DONE_c_int: c_int = WOLFSSL_SHUTDOWN_NOT_DONE as c_int;
pub const WOLFSSL_ERROR_NONE_c_int: c_int = WOLFSSL_ERROR_NONE as c_int;
pub const WOLFSSL_VERIFY_NONE_c_int: c_int = WOLFSSL_VERIFY_NONE as c_int;
pub const WOLFSSL_VERIFY_PEER_c_int: c_int = WOLFSSL_VERIFY_PEER as c_int;
pub const WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT_c_int: c_int =
    WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT as c_int;
pub const WOLFSSL_VERIFY_FAIL_EXCEPT_PSK_c_int: c_int = WOLFSSL_VERIFY_FAIL_EXCEPT_PSK as c_int;
