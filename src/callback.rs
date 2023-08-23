use crate::ssl::DataBuffer;
use bytes::Buf;
use std::ffi::{c_char, c_int, c_void};

/// The custom IO callback documented at [`EmbedRecieve`][0] (whose
/// inputs and outputs we need to emulate).
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-embedreceive
pub unsafe extern "C" fn wolf_tls_read_cb(
    _ssl: *mut wolfssl_sys::WOLFSSL,
    buf: *mut c_char,
    sz: c_int,
    ctx: *mut c_void,
) -> c_int {
    debug_assert!(!_ssl.is_null());
    debug_assert!(!buf.is_null());
    debug_assert!(!ctx.is_null());

    let read_buffer = unsafe { &mut *(ctx as *mut DataBuffer) };

    // If our buffer is empty, there's nothing more to do here. Tell
    // WolfSSL that we need more data
    if read_buffer.is_empty() {
        return wolfssl_sys::IOerrors_WOLFSSL_CBIO_ERR_WANT_READ;
    }

    // Find out how much we should or can copy to WolfSSL. WolfSSL
    // asks for data piecemeal, so often it will ask for just 2 or 5
    // bytes at a time. Passing more will cause it to error. On the
    // other hand though, it might need a 1000 bytes, but all we have
    // is 500 - in which case just send all that we can.
    let num_of_bytes = std::cmp::min(read_buffer.len(), sz as usize);

    // Now for some slight of hand - make the buffer provided by
    // WolfSSL appear as a slice. Despite this being an unsafe piece
    // of code, it will make further interactions far safer by
    // conceptualising the buffer pointer and length together.
    //
    // We use `num_of_bytes` here to ensure that we are always dealing
    // with valid memory
    let wolf_buffer = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, num_of_bytes) };

    // Copy the data into WolfSSL's buffer
    wolf_buffer.copy_from_slice(&read_buffer[..num_of_bytes]);

    // Drop the bytes read into WolfSSL
    Buf::advance(read_buffer, num_of_bytes);

    // WolfSSL expects that we return the number of bytes copied
    num_of_bytes as ::std::os::raw::c_int
}

/// The custom IO callback documented at [`EmbedSend`][0] (whose
/// inputs and outputs we need to emulate).
///
/// Here the assumption is that WolfSSL is writing data _into_ the
/// callback (which will then ship it off somewhere)
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-embedsend
pub unsafe extern "C" fn wolf_tls_write_cb(
    _ssl: *mut wolfssl_sys::WOLFSSL,
    buf: *mut c_char,
    sz: c_int,
    ctx: *mut c_void,
) -> c_int {
    debug_assert!(!_ssl.is_null());
    debug_assert!(!buf.is_null());
    debug_assert!(!ctx.is_null());

    let write_buffer = unsafe { &mut *(ctx as *mut DataBuffer) };

    // Create a slice using the c pointer and length from WolfSSL.
    // This contains the bytes we need to write out
    let wolf_buffer: &[u8] = unsafe { std::slice::from_raw_parts(buf as *const u8, sz as usize) };

    // Copy bytes into our write buffer. Our buffer will resize as
    // needed
    write_buffer.extend_from_slice(wolf_buffer);

    // Return the number of bytes WolfSSL gave us as we can consume
    // all of them. At this point however WolfSSL believes that the
    // send was successful, it has no way to know otherwise
    wolf_buffer.len() as c_int
}
