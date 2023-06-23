use crate::{context::WolfContext, TLS_MAX_RECORD_SIZE};

use bytes::{Buf, BytesMut};
use parking_lot::Mutex;

use std::ptr::NonNull;

#[allow(missing_docs)]
pub struct WolfSession {
    ssl: Mutex<NonNull<wolfssl_sys::WOLFSSL>>,

    // A `Box` because we need a stable pointer address
    callback_read_buffer: Box<CallbackBuffer>,
    callback_write_buffer: Box<CallbackBuffer>,
}

impl WolfSession {
    /// Invokes [`wolfSSL_new`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_new
    pub fn new_from_context(ctx: &WolfContext) -> Option<Self> {
        let ptr = unsafe { wolfssl_sys::wolfSSL_new(ctx.ctx().as_ptr()) };

        let mut session = Self {
            ssl: Mutex::new(NonNull::new(ptr)?),
            callback_read_buffer: Box::new(CallbackBuffer(BytesMut::with_capacity(
                TLS_MAX_RECORD_SIZE,
            ))),
            callback_write_buffer: Box::new(CallbackBuffer(BytesMut::with_capacity(
                TLS_MAX_RECORD_SIZE,
            ))),
        };

        session.register_io_context();

        Some(session)
    }

    /// Gets the current cipher of the session.
    /// If the cipher name is "None", return None.
    pub fn get_current_cipher_name(&self) -> Option<String> {
        let cipher = unsafe { wolfssl_sys::wolfSSL_get_current_cipher(self.ssl.lock().as_ptr()) };
        let cipher = if !cipher.is_null() {
            let name = unsafe {
                let name = wolfssl_sys::wolfSSL_CIPHER_get_name(cipher);
                std::ffi::CStr::from_ptr(name).to_str().ok()?.to_string()
            };
            Some(name)
        } else {
            None
        };

        match cipher {
            Some(x) if x == "None" => None,
            x => x,
        }
    }

    /// Invokes [`wolfSSL_is_init_finished`][0]
    ///
    /// "Init" in this case is the formation of the TLS connection.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_is_init_finished
    pub fn is_init_finished(&self) -> bool {
        match unsafe { wolfssl_sys::wolfSSL_is_init_finished(self.ssl.lock().as_ptr()) } {
            0 => false,
            1 => true,
            _ => unimplemented!("Only 0 or 1 is expected as return value"),
        }
    }
}

impl WolfSession {
    /// Registers a context that will be visible within the custom IO callbacks
    /// tied to this `WOLFSSL` session.
    ///
    /// This is done via [`wolfSSL_SetIOReadCtx`][0] and
    /// [`wolfSSL_SetIOWriteCtx`][1].
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setioreadctx
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setiowritectx
    fn register_io_context(&mut self) {
        let ssl = self.ssl.lock();
        let read_buffer_ptr = &mut self.callback_read_buffer as *mut _ as *mut std::ffi::c_void;
        let write_buffer_ptr = &mut self.callback_write_buffer as *mut _ as *mut std::ffi::c_void;
        unsafe {
            wolfssl_sys::wolfSSL_SetIOReadCtx(ssl.as_ptr(), read_buffer_ptr);
            wolfssl_sys::wolfSSL_SetIOWriteCtx(ssl.as_ptr(), write_buffer_ptr);
        }
    }
}

impl Drop for WolfSession {
    /// Invokes [`wolfSSL_free`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_free
    fn drop(&mut self) {
        unsafe { wolfssl_sys::wolfSSL_free(self.ssl.lock().as_ptr()) }
    }
}

pub(crate) struct CallbackBuffer(BytesMut);

impl std::ops::Deref for CallbackBuffer {
    type Target = BytesMut;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for CallbackBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Buf for CallbackBuffer {
    fn advance(&mut self, cnt: usize) {
        self.0.advance(cnt)
    }

    fn chunk(&self) -> &[u8] {
        self.0.chunk()
    }

    fn remaining(&self) -> usize {
        self.0.remaining()
    }
}
