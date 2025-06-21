use crate::{
    callback::{IOCallbackResult, IOCallbacks},
    context::WolfsslPointer,
    error::{Error, Poll, PollResult, Result},
    CurveGroup, ProtocolVersion, SslVerifyMode, TLS_MAX_RECORD_SIZE,
};

use bytes::{Buf, Bytes, BytesMut};
use thiserror::Error;

use std::{
    ffi::{c_int, c_uchar, c_ushort, c_void},
    time::Duration,
};

#[cfg(feature = "debug")]
use crate::debug::{Tls13SecretCallbacksArg, RANDOM_SIZE};

/// Convert a [`std::io::ErrorKind`] into WOLFSSL_CBIO error as descibed in [`EmbedReceive`][0].
///
/// `would_block` is returned if the variant is
/// [`std::io::ErrorKind::WouldBlock`], since wolfssl has different
/// error names (although under the hood the value is the same). Note
/// that the application is expected to have returned
/// [`IOCallbackResult::WouldBlock`] in this case so we shouldn't be
/// here in the first place, but be tollerant in this case.
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-embedreceive
fn io_errorkind_into_wolfssl_cbio_error(
    kind: std::io::ErrorKind,
    would_block: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    use std::io::ErrorKind::*;
    match kind {
        // Note that WouldBlock also covers EAGAIN errors under the hood.
        WouldBlock => would_block,
        TimedOut => wolfssl_sys::IOerrors_WOLFSSL_CBIO_ERR_TIMEOUT,
        ConnectionReset => wolfssl_sys::IOerrors_WOLFSSL_CBIO_ERR_CONN_RST,
        Interrupted => wolfssl_sys::IOerrors_WOLFSSL_CBIO_ERR_ISR,
        ConnectionAborted => wolfssl_sys::IOerrors_WOLFSSL_CBIO_ERR_CONN_CLOSE,
        _ => wolfssl_sys::IOerrors_WOLFSSL_CBIO_ERR_GENERAL,
    }
}

/// Stores configurations we want to initialize a [`Session`] with.
pub struct SessionConfig<IOCB: IOCallbacks> {
    /// I/O callback handlers
    pub io: IOCB,

    /// If set and the session is DTLS, sets the nonblocking mode.
    pub dtls_use_nonblock: Option<bool>,
    /// If set and the session is DTLS, sets the MTU of the session.
    ///
    /// If value exceeds wolfSSL's `MAX_RECORD_SIZE` (currently 2^14), or
    /// is 0, ignored.
    pub dtls_mtu: Option<u16>,
    /// If set, configures SNI (Server Name Indication) for the session with the
    /// given hostname.
    pub server_name_indicator: Option<String>,
    /// If set, configures the session to check the given domain against the
    /// peer certificate during connection.
    pub checked_domain_name: Option<String>,
    /// If set, specifies a curve group to use for key share
    pub keyshare_group: Option<CurveGroup>,
    /// If set, specifies if fragmented ClientHello (CH) is allowed
    pub dtls13_allow_ch_frag: Option<bool>,
    /// SSL Verify mode
    pub ssl_verify_mode: Option<SslVerifyMode>,
    /// If set, callback will be called for all TLS1.3 secret
    #[cfg(feature = "debug")]
    pub keylogger: Option<Tls13SecretCallbacksArg>,
}

impl<IOCB: IOCallbacks> SessionConfig<IOCB> {
    /// Creates a default [`Self`]. A set of IO callbacks implementing
    /// [`IOCallbacks`] must be provided.
    pub fn new(io: IOCB) -> Self {
        Self {
            io,
            dtls_use_nonblock: Default::default(),
            dtls_mtu: Default::default(),
            server_name_indicator: Default::default(),
            checked_domain_name: Default::default(),
            keyshare_group: Default::default(),
            dtls13_allow_ch_frag: Default::default(),
            ssl_verify_mode: Default::default(),
            #[cfg(feature = "debug")]
            keylogger: Default::default(),
        }
    }

    /// When `cond` is True call `func` on `Self`
    pub fn when<F>(self, cond: bool, func: F) -> Self
    where
        F: FnOnce(Self) -> Self,
    {
        if cond {
            func(self)
        } else {
            self
        }
    }

    /// When `maybe` is Some(_) call `func` on `Self` and the contained value
    pub fn when_some<F, T>(self, maybe: Option<T>, func: F) -> Self
    where
        F: FnOnce(Self, T) -> Self,
    {
        if let Some(t) = maybe {
            func(self, t)
        } else {
            self
        }
    }

    /// Sets [`Self::dtls_use_nonblock`]
    pub fn with_dtls_nonblocking(mut self, is_nonblocking: bool) -> Self {
        self.dtls_use_nonblock = Some(is_nonblocking);
        self
    }

    /// Sets [`Self::dtls13_allow_ch_frag`]
    pub fn with_dtls13_allow_ch_frag(mut self, allow: bool) -> Self {
        self.dtls13_allow_ch_frag = Some(allow);
        self
    }

    /// Sets [`Self::dtls_mtu`]
    pub fn with_dtls_mtu(mut self, mtu: u16) -> Self {
        self.dtls_mtu = Some(mtu);
        self
    }

    /// Sets [`Self::server_name_indicator`]
    pub fn with_sni(mut self, hostname: &str) -> Self {
        self.server_name_indicator = Some(hostname.to_string());
        self
    }

    /// Sets [`Self::checked_domain_name`]
    pub fn with_checked_domain_name(mut self, domain: &str) -> Self {
        self.checked_domain_name = Some(domain.to_string());
        self
    }

    /// Sets [`Self::keyshare_group`]
    pub fn with_keyshare_group(mut self, curve: CurveGroup) -> Self {
        self.keyshare_group = Some(curve);
        self
    }

    /// Sets [`Self::ssl_verify_mode`]
    pub fn with_ssl_verify_mode(mut self, mode: SslVerifyMode) -> Self {
        self.ssl_verify_mode = Some(mode);
        self
    }

    /// Sets [`Self::keylogger`]
    #[cfg(feature = "debug")]
    pub fn with_key_logger(mut self, keylogger: Tls13SecretCallbacksArg) -> Self {
        self.keylogger = Some(keylogger);
        self
    }
}

/// Wraps a `WOLFSSL` pointer, as well as the additional fields needed to
/// write into, and read from, wolfSSL's custom IO callbacks.
pub struct Session<IOCB: IOCallbacks> {
    ssl: WolfsslPointer,

    /// Box so we have a stable address to pass to FFI.
    io: Box<IOCB>,

    #[cfg(feature = "debug")]
    secret_cb: Option<Box<Tls13SecretCallbacksArg>>,
}

/// Error creating a [`Session`] object.
#[derive(Error, Debug)]
pub enum NewSessionError {
    /// `wolfSSL_new` failed
    #[error("Failed to allocate WolfSSL Session")]
    CreateFailed,

    /// A setup operation on the WolfSSL Session
    #[error("Failed to setup SSL session context: {0}: {1}")]
    SetupFailed(&'static str, Error),
}

impl<IOCB: IOCallbacks> Session<IOCB> {
    /// Invokes [`wolfSSL_new`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_new
    pub(crate) fn new_from_wolfssl_pointer(
        ssl: WolfsslPointer,
        config: SessionConfig<IOCB>,
    ) -> std::result::Result<Self, NewSessionError> {
        let mut session = Self {
            ssl,
            io: Box::new(config.io),
            #[cfg(feature = "debug")]
            secret_cb: Default::default(),
        };

        session.register_io_context();

        if let Some(is_nonblocking) = config.dtls_use_nonblock {
            session.dtls_set_nonblock_use(is_nonblocking);
        }

        if let Some(allow_ch_frag) = config.dtls13_allow_ch_frag {
            session
                .dtls13_allow_ch_frag(allow_ch_frag)
                .map_err(|e| NewSessionError::SetupFailed("dtls13_allow_ch_frag", e))?;
        }

        if let Some(mtu) = config.dtls_mtu {
            session.dtls_set_mtu(mtu as c_ushort);
        }

        if let Some(sni) = config.server_name_indicator {
            session
                .set_server_name_indication(&sni)
                .map_err(|e| NewSessionError::SetupFailed("set_server_name_indication", e))?;
        }

        if let Some(name) = config.checked_domain_name {
            session
                .set_domain_name_to_check(&name)
                .map_err(|e| NewSessionError::SetupFailed("set_domain_name_to_check", e))?;
        }

        if let Some(curve) = config.keyshare_group {
            session
                .use_key_share_curve(curve)
                .map_err(|e| NewSessionError::SetupFailed("use_key_share_curve", e))?;
        }

        if let Some(mode) = config.ssl_verify_mode {
            session.set_verify(mode);
        }

        #[cfg(feature = "debug")]
        if let Some(keylogger) = config.keylogger {
            session
                .enable_tls13_keylog(keylogger)
                .map_err(|e| NewSessionError::SetupFailed("keylogger", e))?;
        }

        Ok(session)
    }

    /// Gets the protocol version used for the session.
    /// Invokes [`wolfssl_sys::wolfSSL_version`]
    ///
    /// No online documentation available for `wolfSSL_version`
    pub fn version(&mut self) -> ProtocolVersion {
        // SAFETY: No documentation found for [`wolfSSL_version`][] api,
        // From implementation, the api expects valid pointer to `WOLFSSL`
        let version = unsafe { wolfssl_sys::wolfSSL_version(self.ssl.as_ptr()) };
        match version as u32 {
            wolfssl_sys::TLS1_VERSION => ProtocolVersion::TlsV1_0,
            wolfssl_sys::TLS1_1_VERSION => ProtocolVersion::TlsV1_1,
            wolfssl_sys::TLS1_2_VERSION => ProtocolVersion::TlsV1_2,
            wolfssl_sys::TLS1_3_VERSION => ProtocolVersion::TlsV1_3,
            wolfssl_sys::DTLS1_VERSION => ProtocolVersion::DtlsV1_0,
            wolfssl_sys::DTLS1_2_VERSION => ProtocolVersion::DtlsV1_2,
            wolfssl_sys::DTLS1_3_VERSION => ProtocolVersion::DtlsV1_3,
            wolfssl_sys::SSL2_VERSION => ProtocolVersion::SslV2,
            wolfssl_sys::SSL3_VERSION => ProtocolVersion::SslV3,
            _ => ProtocolVersion::Unknown,
        }
    }

    /// Gets the current cipher of the session.
    /// If the cipher name is "None", return None.
    pub fn get_current_cipher_name(&mut self) -> Option<String> {
        // SAFETY: [`wolfSSL_get_current_cipher`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.o
        // Return value is the pointer inside the ssl session. Caller can read it safely
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_get_current_cipher
        // [1]: https://www.wolfssl.com/doxygen/group__IO.html#ga0a2985d2088f0b331a4949860fda400d
        let cipher = unsafe { wolfssl_sys::wolfSSL_get_current_cipher(self.ssl.as_ptr()) };
        let cipher = if !cipher.is_null() {
            // SAFETY: Documentation for [`wolfSSL_CIPHER_get_name`][0] ([also][1]) is not clear about the memory usage
            // From implementation, return value is the pointer to static buffer. Caller can read it safely
            //
            // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_cipher_get_name
            // [1]: https://www.wolfssl.com/doxygen/group__IO.html#ga1d77df578e8cebd9d75d2211b927d868
            let c_name = unsafe { wolfssl_sys::wolfSSL_CIPHER_get_name(cipher) };
            if c_name.is_null() {
                None
            } else {
                // SAFETY: If `wolfSSL_CIPHER_get_name` returns
                // non-NULL then it returns a valid C string.
                //
                // Since the return value is to a static buffer it is
                // within a single allocated object.
                //
                // Since the return value is to a static buffer it
                // outlives any possible 'a.
                //
                // No cipher suite name is `isize::MAX` long.
                Some(unsafe { std::ffi::CStr::from_ptr(c_name).to_str().ok()?.to_string() })
            }
        } else {
            None
        };

        match cipher {
            Some(x) if x == "None" => None,
            x => x,
        }
    }

    /// Sets verification method for remote peers
    pub fn set_verify(&mut self, mode: SslVerifyMode) {
        // SAFETY: [`wolfSSL_set_verify`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`
        // Third parameter `verify_callback` if valid, will be called when verification fails.
        // But we send `None` since we do not use this additional functionality
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_set_verify
        // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#gaf9198658e31dd291088be18262ef2354
        unsafe { wolfssl_sys::wolfSSL_set_verify(self.ssl.as_ptr(), mode.into(), None) };
    }

    /// Gets the current curve of the session if ECDH was used,
    /// otherwise `None`.
    pub fn get_current_curve_name(&mut self) -> Option<String> {
        // SAFETY: No online documentation available for
        // `wolfSSL_get_curve_name`. In code documentation states:
        //
        // > Return the name of the curve used for key exchange as a printable string.
        // >
        // > ssl  The SSL/TLS object.
        // > returns NULL if ECDH was not used, otherwise the name as a string.
        let curve = unsafe { wolfssl_sys::wolfSSL_get_curve_name(self.ssl.as_ptr()) };
        if !curve.is_null() {
            // SAFETY: Per above if `wolfSSL_get_curve_name` returns
            // non-null then the result is a valid string.
            unsafe { Some(std::ffi::CStr::from_ptr(curve).to_str().ok()?.to_string()) }
        } else {
            None
        }
    }

    /// Invokes [`wolfSSL_is_init_finished`][0]
    ///
    /// "Init" in this case is the formation of the TLS connection.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_is_init_finished
    pub fn is_init_finished(&mut self) -> bool {
        // SAFETY: [`wolfSSL_is_init_finished`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        // Documentation for return values seems incorrect though, having same text for both success and error case.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__TLS.html#function-wolfssl_is_init_finished
        // [1]: https://www.wolfssl.com/doxygen/group__TLS.html#gaa0bd0ae911e350d1e64b0cc9d3c8292b
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe { wolfssl_sys::wolfSSL_is_init_finished(self.ssl.as_ptr()) } {
            0 => false,
            1 => true,
            e => unreachable!("wolfSSL_is_init_finished: {e:?}"),
        }
    }

    /// Get a reference to the IOCB embedded in this session
    pub fn io_cb(&self) -> &IOCB {
        self.io.as_ref()
    }

    /// Get a mutable reference to the IOCB embedded in this session
    pub fn io_cb_mut(&mut self) -> &mut IOCB {
        self.io.as_mut()
    }

    /// Invokes [`wolfSSL_negotiate`][0] *once*.
    ///
    /// The distinction is important because it takes more than one invocation
    /// to successfully form a secure session.
    ///
    /// This method will trigger WolfSSL's IO callbacks
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_negotiate
    pub fn try_negotiate(&mut self) -> PollResult<()> {
        // SAFETY: [`wolfSSL_negotiate`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_negotiate
        // [1]: https://www.wolfssl.com/doxygen/group__IO.html#gaf6780235ee9a7abe3f704a585eb77849
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe { wolfssl_sys::wolfSSL_negotiate(self.ssl.as_ptr()) } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(Poll::Ready(())),
            x @ wolfssl_sys::wolfSSL_ErrorCodes_WOLFSSL_FATAL_ERROR => match self.get_error(x) {
                wolfssl_sys::WOLFSSL_ERROR_WANT_READ_c_int => Ok(Poll::PendingRead),
                wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE_c_int => Ok(Poll::PendingWrite),
                wolfssl_sys::wolfSSL_ErrorCodes_APP_DATA_READY
                    if self.is_secure_renegotiation_supported() =>
                {
                    self.handle_app_data().map(Poll::AppData)
                }
                e => Err(Error::fatal(e)),
            },
            e => Err(Error::fatal(e)),
        }
    }

    /// Invokes [`wolfSSL_shutdown`][0] *once*.
    ///
    /// Returns `Poll::Ready(true)` if the connection has been fully
    /// (bidirectionally) shutdown, including having seen the "closing
    /// notify" message from the peer.
    ///
    /// Returns `Poll::Ready(false)` if the connection has only been
    /// shutdown from this end. If you intend to reuse the connection
    /// then you must call `try_shutdown` again. You do not need to
    /// poll for new I/O first, `Poll::Pending{Read,Write}` will be
    /// returned if I/O is required.
    ///
    /// If there is no intent to reuse the connection, you do not need
    /// to await for a response from the other side and
    /// `Poll::Ready(false)` can be ignored.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_shutdown
    pub fn try_shutdown(&mut self) -> PollResult<bool> {
        // SAFETY: [`wolfSSL_shutdown`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_shutdown
        // [1]: https://www.wolfssl.com/doxygen/group__TLS.html#ga51f54ec99e4d87f4b25a92fe031439ae
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe { wolfssl_sys::wolfSSL_shutdown(self.ssl.as_ptr()) } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(Poll::Ready(true)),
            wolfssl_sys::WOLFSSL_SHUTDOWN_NOT_DONE_c_int => Ok(Poll::Ready(false)),
            x @ wolfssl_sys::wolfSSL_ErrorCodes_WOLFSSL_FATAL_ERROR => match self.get_error(x) {
                wolfssl_sys::WOLFSSL_ERROR_WANT_READ_c_int => Ok(Poll::PendingRead),
                wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE_c_int => Ok(Poll::PendingWrite),
                wolfssl_sys::wolfSSL_ErrorCodes_APP_DATA_READY
                    if self.is_secure_renegotiation_supported() =>
                {
                    self.handle_app_data().map(Poll::AppData)
                }
                x => Err(Error::fatal(x)),
            },
            e => Err(Error::fatal(e)),
        }
    }

    /// Invokes [`wolfSSL_write`][0] *once*.
    ///
    /// Given a buffer, consumes as much of it as possible, writing into the
    /// network.
    ///
    /// This method will return the number of bytes that was successfully
    /// written into wolfSSL.
    ///
    /// It is not guaranteed that the entire buffer will be consumed, since we
    /// only invoke `wolfSSL_write` once.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_write
    //
    // Note that even if no data was consumed, WolfSSL might take this
    // opportunity to update its internal state (for example, if it needs to
    // update encryption keys). This can be seen in
    // [`Self::trigger_update_keys`].
    pub fn try_write(&mut self, data_in: &mut BytesMut) -> PollResult<usize> {
        match self.try_write_slice(data_in) {
            res @ Ok(Poll::Ready(len)) => {
                data_in.advance(len);
                res
            }
            other => other,
        }
    }

    /// Like try_write, but reads from a simple slice instead.
    pub fn try_write_slice(&mut self, data_in: &[u8]) -> PollResult<usize> {
        // SAFETY: [`wolfSSL_write`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_write
        // [1]: https://www.wolfssl.com/doxygen/group__IO.html#gad6cbb3cb90e4d606e9507e4ec06197df
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe {
            wolfssl_sys::wolfSSL_write(
                self.ssl.as_ptr(),
                data_in.as_ptr() as *const c_void,
                data_in.len() as c_int,
            )
        } {
            x if x > 0 => Ok(Poll::Ready(x as usize)),
            x @ (0 | wolfssl_sys::wolfSSL_ErrorCodes_WOLFSSL_FATAL_ERROR) => {
                match self.get_error(x) {
                    wolfssl_sys::WOLFSSL_ERROR_NONE_c_int => Ok(Poll::Ready(0)),
                    wolfssl_sys::WOLFSSL_ERROR_WANT_READ_c_int => Ok(Poll::PendingRead),
                    wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE_c_int => Ok(Poll::PendingWrite),
                    wolfssl_sys::wolfSSL_ErrorCodes_APP_DATA_READY
                        if self.is_secure_renegotiation_supported() =>
                    {
                        self.handle_app_data().map(Poll::AppData)
                    }
                    e => Err(Error::fatal(e)),
                }
            }
            e => Err(Error::fatal(e)),
        }
    }

    /// Invokes [`wolfSSL_read`][0] *once*.
    ///
    /// This can be thought of as the inverse to [`Self::try_write`]:
    /// - It reads data from WolfSSL into a buffer.
    /// - It appends data to the given buffer, up to its given capacity.
    ///   - It does not alter existing data inside the buffer.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_read
    //
    // Like [`Self::try_write`], we call through to `wolfSSL_read` even if there
    // is no space to allow WolfSSL's internal state to advance.
    pub fn try_read(&mut self, data_out: &mut BytesMut) -> PollResult<usize> {
        let buf = data_out.spare_capacity_mut();
        // SAFETY: the length is obviously correct
        match unsafe { self.try_read_ptr(buf.as_mut_ptr() as *mut c_void, buf.len() as c_int) } {
            res @ Ok(Poll::Ready(read_len)) => {
                // SAFETY: wolfSSL told us this memory region is now initialized
                unsafe {
                    data_out.set_len(data_out.len() + read_len);
                }
                res
            }
            other => other,
        }
    }

    /// Like try_read, but writes into a mutable slice instead.
    pub fn try_read_slice(&mut self, data_out: &mut [u8]) -> PollResult<usize> {
        // SAFETY: the length is obviously correct
        unsafe {
            self.try_read_ptr(
                data_out.as_mut_ptr() as *mut c_void,
                data_out.len() as c_int,
            )
        }
    }

    unsafe fn try_read_ptr(&mut self, out_ptr: *mut c_void, out_len: c_int) -> PollResult<usize> {
        // SAFETY: [`wolfSSL_read`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        // The input `buf` is a valid mutable buffer, with proper length.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_read
        // [1]: https://www.wolfssl.com/doxygen/group__IO.html#ga80c3ccd3c0441c77307df3afe88a5c35
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe { wolfssl_sys::wolfSSL_read(self.ssl.as_ptr(), out_ptr, out_len) } {
            x if x > 0 => Ok(Poll::Ready(x as usize)),
            x @ (0 | wolfssl_sys::wolfSSL_ErrorCodes_WOLFSSL_FATAL_ERROR) => {
                match self.get_error(x) {
                    wolfssl_sys::WOLFSSL_ERROR_WANT_READ_c_int => Ok(Poll::PendingRead),
                    wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE_c_int => Ok(Poll::PendingWrite),
                    wolfssl_sys::WOLFSSL_ERROR_NONE_c_int => Ok(Poll::Ready(0)),
                    wolfssl_sys::wolfSSL_ErrorCodes_APP_DATA_READY
                        if self.is_secure_renegotiation_supported() =>
                    {
                        self.handle_app_data().map(Poll::AppData)
                    }
                    e => Err(Error::fatal(e)),
                }
            }
            e => Err(Error::fatal(e)),
        }
    }

    /// Checks if this session supports secure renegotiation
    ///
    /// Only some D/TLS connections support secure renegotiation, so this method
    /// checks if it's something we can do here.
    pub fn is_secure_renegotiation_supported(&mut self) -> bool {
        // SAFETY: No documentation available for `wolfSSL_SSL_get_secure_renegotiation_support`
        // But based on the implementation, it is safe to call the api as long as the `ssl` pointer points
        // to valid `WOLFSSL` struct
        match unsafe {
            wolfssl_sys::wolfSSL_SSL_get_secure_renegotiation_support(self.ssl.as_ptr())
        } {
            0 => false,
            1 => true,
            e => unreachable!("wolfSSL_SSL_get_secure_renegotiation_support: {e:?}"),
        }
    }

    /// Checks if there is an ongoing secure renegotiation triggered by
    /// [`Self::try_rehandshake`].
    //
    // NOTE: No documentation found for `wolfSSL_SSL_renegotiate_pending`
    pub fn is_secure_renegotiation_pending(&mut self) -> bool {
        // SAFETY: No documentation available for `wolfSSL_SSL_renegotiate_pending`
        // But based on the implementation, it is safe to call the api as long as the `ssl` pointer points
        // to valid `WOLFSSL` struct
        match unsafe { wolfssl_sys::wolfSSL_SSL_renegotiate_pending(self.ssl.as_ptr()) } {
            0 => false,
            1 => true,
            e => unreachable!("wolfSSL_SSL_renegotiate_pending: {e:?}"),
        }
    }

    /// Invokes [`wolfSSL_Rehandshake`][0] *once*.
    ///
    /// Is a no-op unless the session supports secure renegotiation.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html?query=wolfssl_rehandshake#function-wolfssl_rehandshake
    pub fn try_rehandshake(&mut self) -> PollResult<()> {
        if !self.is_secure_renegotiation_supported() {
            return Ok(Poll::Ready(()));
        }

        // SAFETY: [`wolfSSL_Rehandshake`][0] ([also][1]) expects valid pointer to `WOLFSSL` and since the `WOLFSSL` struct
        // can be used in multiple threads based on [`Library design`][2], protected by the requirement for `&mut self` in
        // `WolfsslPointer::as_ptr()`.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_rehandshake
        // [1]: https://www.wolfssl.com/doxygen/group__IO.html#ga7ba02472014a68d0717ca9243d9dd646
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe { wolfssl_sys::wolfSSL_Rehandshake(self.ssl.as_ptr()) } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(Poll::Ready(())),
            x @ wolfssl_sys::wolfSSL_ErrorCodes_WOLFSSL_FATAL_ERROR => match self.get_error(x) {
                wolfssl_sys::WOLFSSL_ERROR_WANT_READ_c_int => Ok(Poll::PendingRead),
                wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE_c_int => Ok(Poll::PendingWrite),
                wolfssl_sys::wolfSSL_ErrorCodes_APP_DATA_READY
                    if self.is_secure_renegotiation_supported() =>
                {
                    self.handle_app_data().map(Poll::AppData)
                }
                e => Err(Error::fatal(e)),
            },
            e => Err(Error::fatal(e)),
        }
    }

    /// Invokes [`wolfSSL_update_keys`][0] *once*
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_update_keys
    pub fn try_trigger_update_key(&mut self) -> PollResult<()> {
        let protocol_version = self.version();
        if !protocol_version.is_tls_13() && !protocol_version.is_dtls_13() {
            return Ok(Poll::Ready(()));
        }

        if !self.is_init_finished() {
            return Ok(Poll::Ready(()));
        }

        // SAFETY: [`wolfSSL_update_keys`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        // Other requirements including the protocol version and handshake completed which is checked above
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_update_keys
        // [1]: https://www.wolfssl.com/doxygen/group__IO.html#ga38ef7eb0a15b65f3b68d2490dd0535a0
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe { wolfssl_sys::wolfSSL_update_keys(self.ssl.as_ptr()) } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(Poll::Ready(())),
            e @ wolfssl_sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG => {
                unreachable!("wolfSSL_update_keys: {e:?}")
            }
            wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE_c_int => Ok(Poll::PendingWrite),

            e => Err(Error::fatal(e)),
        }
    }

    /// Invokes [`wolfSSL_key_update_response`][0]
    ///
    /// Returns `true` if the client has sent a key update and is expecting a
    /// response, `false` otherwise.
    ///
    /// Note that this is a TLS/DTLS 1.3 only feature. If the session is not TLS/DTLS 1.3
    /// we will always return false.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_key_update_response
    pub fn is_update_keys_pending(&mut self) -> bool {
        let protocol_version = self.version();
        if !protocol_version.is_tls_13() && !protocol_version.is_dtls_13() {
            return false;
        }

        let mut required = std::mem::MaybeUninit::<c_int>::uninit();

        // SAFETY: [`wolfSSL_key_update_response`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        // Other requirements including the protocol version TLS 1.3 is checked above
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_key_update_response
        // [1]: https://www.wolfssl.com/doxygen/group__IO.html#ga2f38357d4d7fba294745516caa8f4180
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe {
            wolfssl_sys::wolfSSL_key_update_response(self.ssl.as_ptr(), required.as_mut_ptr())
        } {
            0 => {}
            // panic on non-success, because `ssl` is always non-null and the
            // method here must be TLS1.3
            e => unreachable!("wolfSSL_key_update_response: {e:?}"),
        }

        // SAFETY: Based on `wolfSSL_key_update_response`][0], required will be populated if the api returns success.
        // So safety to call `assume_init()` on success case. On error case we paniced above!
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__IO.html#function-wolfssl_key_update_response
        match unsafe { required.assume_init() } {
            1 => true,
            0 => false,
            e => unreachable!("wolfSSL_key_update_response: unexpected value: {e:?}"),
        }
    }

    /// Invokes [`wolfSSL_dtls_get_current_timeout`][0].
    ///
    /// This reports how long the calling application needs to wait for
    /// available received data, in seconds.
    ///
    /// WolfSSL implements a backoff, so the returned value will likely change.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls_get_current_timeout
    pub fn dtls_current_timeout(&mut self) -> Duration {
        if !self.is_dtls() {
            log::debug!("Session is not configured for DTLS");
        }

        // SAFETY: [`wolfSSL_dtls_get_current_timeout`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        // Other requirements including the protocol version DTLS is checked above
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls_get_current_timeout
        // [1]: https://www.wolfssl.com/doxygen/ssl_8h.html#a07da5ada53a2a68ee8e7a6dab9b5f429
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe { wolfssl_sys::wolfSSL_dtls_get_current_timeout(self.ssl.as_ptr()) } {
            e @ wolfssl_sys::wolfCrypt_ErrorCodes_NOT_COMPILED_IN => {
                unreachable!("wolfSSL_dtls_get_current_timeout: {e:?}")
            }
            x if x > 0 => Duration::from_secs(x as u64),
            e => unreachable!("wolfSSL_dtls_get_current_timeout: {e:?}"),
        }
    }

    /// Invokes [`wolfSSL_dtls_set_timeout_init`][0]
    ///
    /// This sets both the initial timeout (the value WolfSSL uses before any
    /// kind of backoff), and the current, ongoing timeout if there is one.
    ///
    /// There are multiple timeout values because WolfSSL has a backoff.
    ///
    /// The duration:
    /// - Should not be 0
    /// - Should not exceed the current maximum timeout (refer to
    ///   [`Self::dtls_set_max_timeout`]).
    ///
    /// Truncates to the nearest second.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls_set_timeout_init
    pub fn dtls_set_timeout(&mut self, time: Duration) -> Result<()> {
        if !self.is_dtls() {
            log::debug!("Session is not configured for DTLS");
        }

        // SAFETY: [`wolfSSL_dtls_set_timeout_init`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        // Other requirements including the protocol version DTLS is checked above
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_dtls_set_timeout_init
        // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#ga1dd3c408c996a80b9abfae8f74645d21
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe {
            wolfssl_sys::wolfSSL_dtls_set_timeout_init(self.ssl.as_ptr(), time.as_secs() as c_int)
        } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(()),
            x @ wolfssl_sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG => Err(Error::fatal(x)),
            e => Err(Error::fatal(e)),
        }
    }

    /// Invokes [`wolfSSL_dtls_set_timeout_max`][0]
    ///
    /// This sets the maximum amount of time WolfSSL is allowed to wait before
    /// declaring a timeout, including backoff. (defaults to `DTLS_TIMEOUT_MAX`)
    ///
    /// Returns an error if the argument is set to 0, exceeds WolfSSL's internal
    /// limits, or if the argument is lower than the current timeout as set by
    /// [`Self::dtls_set_timeout`].
    ///
    /// Truncates to the nearest second.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls_set_timeout_max
    pub fn dtls_set_max_timeout(&mut self, time: Duration) -> Result<()> {
        if !self.is_dtls() {
            log::debug!("Session is not configured for DTLS");
        }

        // SAFETY: [`wolfSSL_dtls_set_timeout_max`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        // Other requirements including the protocol version DTLS is checked above
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls_set_timeout_max
        // [1]: https://www.wolfssl.com/doxygen/ssl_8h.html#a10d57d8c34afabdf6242b9cb164485be
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe {
            wolfssl_sys::wolfSSL_dtls_set_timeout_max(self.ssl.as_ptr(), time.as_secs() as c_int)
        } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(()),
            x @ wolfssl_sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG => Err(Error::fatal(x)),
            e => Err(Error::fatal(e)),
        }
    }

    /// Invokes [`wolfSSL_dtls_got_timeout`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls_got_timeout
    pub fn dtls_has_timed_out(&mut self) -> Poll<bool> {
        if !self.is_dtls() {
            log::debug!("Session is not configured for DTLS");
        }

        // SAFETY: [`wolfSSL_dtls_got_timeout`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls_got_timeout
        // [1]: https://www.wolfssl.com/doxygen/ssl_8h.html#a86c630a78e966b768332c5b19e485a51
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe { wolfssl_sys::wolfSSL_dtls_got_timeout(self.ssl.as_ptr()) } {
            e @ wolfssl_sys::wolfCrypt_ErrorCodes_NOT_COMPILED_IN => {
                unreachable!("wolfSSL_dtls_got_timeout: {e:?}")
            }
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Poll::Ready(false),
            x @ wolfssl_sys::wolfSSL_ErrorCodes_WOLFSSL_FATAL_ERROR => match self.get_error(x) {
                wolfssl_sys::WOLFSSL_ERROR_WANT_READ_c_int => Poll::PendingRead,
                wolfssl_sys::WOLFSSL_ERROR_WANT_WRITE_c_int => Poll::PendingWrite,
                _ => Poll::Ready(true),
            },
            e => unreachable!("wolfSSL_dtls_got_timeout: {e:?}"),
        }
    }

    /// Invokes [`wolfSSL_dtls13_use_quick_timeout`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls13_use_quick_timeout
    pub fn dtls13_use_quick_timeout(&mut self) -> bool {
        if !self.is_dtls() {
            log::debug!("Session is not configured for DTLS");
            return false;
        }

        // SAFETY: [`wolfSSL_dtls13_use_quick_timeout`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls13_use_quick_timeout
        // [1]: https://www.wolfssl.com/doxygen/ssl_8h.html#a61f3b53cb0397dd1debc8b8daaa490c2
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        0 != unsafe { wolfssl_sys::wolfSSL_dtls13_use_quick_timeout(self.ssl.as_ptr()) }
    }

    /// Invokes [`wolfSSL_dtls13_allow_ch_frag`][0]
    ///
    /// [0]: https://github.com/wolfSSL/wolfssl/blob/v5.6.4-stable/src/dtls13.c#L2835
    pub fn dtls13_allow_ch_frag(&mut self, enabled: bool) -> Result<()> {
        if !self.is_dtls() {
            log::debug!("Session is not configured for DTLS");
            return Err(Error::fatal(wolfssl_sys::WOLFSSL_FAILURE_c_int));
        }

        // SAFETY: `wolfSSL_dtls13_allow_ch_frag` is
        // undocumented. However from the implementation[0] it expects a
        // valid pointer to `WOLFSSL`. Per the [Library design][1]
        // access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`..
        //
        // It returns either WOLFSSL_SUCCESS or WOLFSSL_FAILURE.
        //
        // [0]: https://github.com/wolfSSL/wolfssl/blob/v5.6.4-stable/src/dtls13.c#L2835
        // [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe {
            wolfssl_sys::wolfSSL_dtls13_allow_ch_frag(self.ssl.as_ptr(), enabled as i32)
        } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(()),
            e @ wolfssl_sys::WOLFSSL_FAILURE_c_int => Err(Error::fatal(e)),
            e => Err(Error::fatal(e)),
        }
    }

    unsafe extern "C" fn io_recv_shim(
        _ssl: *mut wolfssl_sys::WOLFSSL,
        buf: *mut ::std::os::raw::c_char,
        sz: ::std::os::raw::c_int,
        ctx: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int {
        debug_assert!(!_ssl.is_null());
        debug_assert!(!buf.is_null());
        debug_assert!(!ctx.is_null());

        // SAFETY:
        // We know that this pointer is to the contents of a `Box`
        // owned by the `Session`. See `register_io_context` below for
        // an argument as to why IO will be stopped (by releasing
        // `WOLFSSL`) before that box is dropped.
        //
        // The `io` (type: `IOCB`) is owned by the `Session` and we
        // know that `try_read` holds an exclusive (`&mut`) reference
        // further up the callchain. Therefore we can recover this
        // exclusive reference to `IOCB`.
        let io = unsafe { &mut *(ctx as *mut IOCB) };

        // SAFETY: Per the callback rules for `wolfSSL_SSLSetIORecv`
        // (see [`wolfSSL_CTX_SetIORecv`][0] for related docs) `buf`
        // is valid for `sz` bytes.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_ctx_setiorecv
        let buf = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, sz as usize) };

        match io.recv(buf) {
            IOCallbackResult::Ok(nr) => nr as std::os::raw::c_int,
            IOCallbackResult::WouldBlock => wolfssl_sys::IOerrors_WOLFSSL_CBIO_ERR_WANT_READ,
            IOCallbackResult::Err(err) => io_errorkind_into_wolfssl_cbio_error(
                err.kind(),
                wolfssl_sys::IOerrors_WOLFSSL_CBIO_ERR_WANT_READ,
            ),
        }
    }

    unsafe extern "C" fn io_send_shim(
        _ssl: *mut wolfssl_sys::WOLFSSL,
        buf: *mut ::std::os::raw::c_char,
        sz: ::std::os::raw::c_int,
        ctx: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int {
        debug_assert!(!_ssl.is_null());
        debug_assert!(!buf.is_null());
        debug_assert!(!ctx.is_null());

        // SAFETY: We know that this pointer is to the contents of a `Box`
        // owned by the `Session`. See `register_io_context` below for
        // an argument as to why IO will be stopped (by releasing
        // `WOLFSSL`) before that box is dropped.
        //
        // The `io` (type: `IOCB`) is owned by the `Session` and we
        // know that `try_write` holds an exclusive (`&mut`) reference
        // further up the callchain. Therefore we can recover this
        // exclusive reference to `IOCB`.
        let io = unsafe { &mut *(ctx as *mut IOCB) };

        // SAFETY: Per the callback rules for `wolfSSL_SSLSetIOSend` (see [`wolfSSL_CTX_SetIORecv`][0] for
        // related docs) `buf` is valid for `sz` bytes.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_ctx_setiorecv
        let buf = unsafe { std::slice::from_raw_parts(buf as *mut u8, sz as usize) };

        match io.send(buf) {
            IOCallbackResult::Ok(nr) => nr as std::os::raw::c_int,
            IOCallbackResult::WouldBlock => wolfssl_sys::IOerrors_WOLFSSL_CBIO_ERR_WANT_WRITE,
            IOCallbackResult::Err(err) => io_errorkind_into_wolfssl_cbio_error(
                err.kind(),
                wolfssl_sys::IOerrors_WOLFSSL_CBIO_ERR_WANT_WRITE,
            ),
        }
    }

    /// Registers a context that will be visible within the custom IO callbacks
    /// tied to this `WOLFSSL` session.
    ///
    /// This is done via `wolfSSL_SSLSetIORecv` and
    /// `wolfSSL_SSLSetIOSend` (see [`wolfSSL_CTX_SetIORecv`][0] for
    /// related docs) [`wolfSSL_SetIOReadCtx`][1] and
    /// [`wolfSSL_SetIOWriteCtx`][2].
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_ctx_setiorecv
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setioreadctx
    /// [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_setiowritectx
    fn register_io_context(&mut self) {
        // SAFETY: `Self::io_recv_shim is 'static so must live longer than `self.ssl`.
        unsafe {
            wolfssl_sys::wolfSSL_SSLSetIORecv(self.ssl.as_ptr(), Some(Self::io_recv_shim));
        }
        // SAFETY: `Self::io_send_shim is 'static so must live longer than `self.ssl`.
        unsafe {
            wolfssl_sys::wolfSSL_SSLSetIOSend(self.ssl.as_ptr(), Some(Self::io_send_shim));
        }

        let io = &mut *self.io as *mut IOCB as *mut std::ffi::c_void;

        // SAFETY:
        // `io` here is behind a `Box<>` (`self.io`) so the address is stable.
        //
        // We free `self.ssl` (the `wolfssl_sys::WOLFSSL`) on drop of
        // `self` so we release (and thus quiesce) any use of the io
        // callbacks before `io` can be dropped.
        //
        // Therefore `io` here is valid for as long as it needs to be.
        unsafe {
            wolfssl_sys::wolfSSL_SetIOReadCtx(self.ssl.as_ptr(), io);
        }
        // SAFETY: As above
        unsafe {
            wolfssl_sys::wolfSSL_SetIOWriteCtx(self.ssl.as_ptr(), io);
        }
    }

    /// Extracts a given error code from this session, by invoking
    /// [`wolfSSL_get_error`][0].
    ///
    /// This is stateful, and collects the error of the previous invoked method.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Debug.html#function_wolfssl_get_error
    fn get_error(&mut self, ret: c_int) -> c_int {
        // SAFETY: [`wolfSSL_get_error`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_get_error
        // [1]: https://www.wolfssl.com/doxygen/group__Debug.html#gaafd5671d443fa684913ba5955a4eb591
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        unsafe { wolfssl_sys::wolfSSL_get_error(self.ssl.as_ptr(), ret) }
    }

    /// During secure renegotiation, wolfssl allows the user to send and receive data.
    ///
    /// If data is detected, WolfSSL will return a `APP_DATA_READY` code, it is then
    /// expected that we immediately read this data, or risk it dropping.
    ///
    /// Since every WolfSSL TLS API could raise this error, the logic is
    /// centralized here, in this helper function.
    //
    // It's implied that the data has already arrived and `wolfSSL_read` will
    // not return a `WANT_READ` or similar error code, so if we see them we will
    // convert it to an error.
    fn handle_app_data(&mut self) -> Result<Bytes> {
        debug_assert!(self.is_secure_renegotiation_supported());

        let mut buf = BytesMut::with_capacity(TLS_MAX_RECORD_SIZE);
        // Collect the appdata wolfssl kindly informed us about.
        match self.try_read(&mut buf) {
            Ok(Poll::Ready(_)) => Ok(buf.freeze()),
            Err(Error::Fatal(e) | Error::AppData(e)) => Err(Error::AppData(e)),
            Ok(Poll::PendingRead | Poll::PendingWrite) => {
                unreachable!("App data is ready, so why are we waiting?")
            }
            // Lightway Core (C) does recurse, but only seems to
            // care about the last wolfssl_read, which likely
            // means that this won't recurse.
            Ok(Poll::AppData(_)) => {
                unreachable!("We assume that no nested calls are possible.")
            }
        }
    }

    /// Invokes [`wolfSSL_set_using_nonblock`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_set_using_nonblock
    fn dtls_set_nonblock_use(&mut self, is_nonblock: bool) {
        if !self.is_dtls() {
            log::debug!("Session is not configured for DTLS");
            return;
        }

        // SAFETY: [`wolfSSL_dtls_set_using_nonblock`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        // Other requirements including the protocol version DTLS is checked above
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls_set_using_nonblock
        // [1]: https://www.wolfssl.com/doxygen/ssl_8h.html#a585412eb9473686f4d65b971c8afc223
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        unsafe {
            wolfssl_sys::wolfSSL_dtls_set_using_nonblock(self.ssl.as_ptr(), is_nonblock as c_int)
        }
    }

    /// Invokes `wolfSSL_dtls_set_mtu`
    ///
    /// Refer to [`SessionConfig::dtls_mtu`] for documentation of constraints on
    /// what values `mtu` can be.
    fn dtls_set_mtu(&mut self, mtu: c_ushort) {
        if !self.is_dtls() {
            log::debug!("Session is not configured for DTLS");
            return;
        }

        if mtu > 2u16.pow(14) {
            log::warn!("Attempted to set MTU to greater than WolfSSL's MAX_RECORD_SIZE");
            return;
        }

        if mtu == 0 {
            log::warn!("Attempted to set MTU to 0");
            return;
        }

        // SAFETY: No documentation found for `wolfSSL_dtls_set_mtu` api,
        // From implementation, the api expects valid pointer to `WOLFSSL`
        match unsafe { wolfssl_sys::wolfSSL_dtls_set_mtu(self.ssl.as_ptr(), mtu) } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => {}
            e => unreachable!("wolfSSL_dtls_set_mtu: {e:?}"),
        }
    }

    /// Invokes [`wolfSSL_dtls`][0]
    ///
    /// Returns `true` if this session is configured for DTLS.
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls
    fn is_dtls(&mut self) -> bool {
        // SAFETY: [`wolfSSL_dtls`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_dtls
        // [1]: https://www.wolfssl.com/doxygen/ssl_8h.html#a298a34e67ad57069d88f6e626df139a1
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe { wolfssl_sys::wolfSSL_dtls(self.ssl.as_ptr()) } {
            1 => true,
            0 => false,
            e => unreachable!("wolfSSL_dtls: {e:?}"),
        }
    }

    /// Invokes [`wolfSSL_UseSNI`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_usesni
    fn set_server_name_indication(&mut self, sni: &String) -> Result<()> {
        let bytes = sni.as_bytes();
        // SAFETY: [`wolfSSL_UseSNI`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        // Api also takes `data` and `size` to get the SNI name, so null terminated string is not required
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_usesni
        // [1]: https://www.wolfssl.com/doxygen/ssl_8h.html#a871070b101b579dc4663217b1c3fbcd4
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe {
            wolfssl_sys::wolfSSL_UseSNI(
                self.ssl.as_ptr(),
                wolfssl_sys::WOLFSSL_SNI_HOST_NAME as c_uchar,
                bytes.as_ptr() as *const c_void,
                bytes.len() as c_ushort,
            )
        } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(()),
            e @ wolfssl_sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG => {
                unreachable!("wolfSSL_UseSNI: {e:?}")
            }
            e => Err(Error::fatal(e)),
        }
    }

    fn set_domain_name_to_check(&mut self, domain_name: &str) -> Result<()> {
        let domain_name = std::ffi::CString::new(domain_name.to_string())
            .expect("Input string '{domain_name:?}' contains an interior NULL");

        // SAFETY: [`wolfSSL_check_domain_name`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        // Documentation does not state explicitly that `dn` (domain name) should be a null terminated string
        // Based on example (and of course no `size` arg), we are constructing Cstring
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_check_domain_name
        // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#gab9b75f5fb10ce88f0026c57716858074
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe {
            wolfssl_sys::wolfSSL_check_domain_name(
                self.ssl.as_ptr(),
                domain_name.as_c_str().as_ptr(),
            )
        } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(()),
            x @ wolfssl_sys::WOLFSSL_FAILURE_c_int => Err(Error::fatal(self.get_error(x))),
            e => Err(Error::fatal(e)),
        }
    }

    ///  Invokes [`wolfSSL_UseKeyShare`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_usekeyshare
    fn use_key_share_curve(&mut self, curve: CurveGroup) -> Result<()> {
        // SAFETY: [`wolfSSL_UseKeyShare`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_usekeyshare
        // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#gac2d00ac65513f10e0ccd1b67d9a99e3d
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        match unsafe {
            wolfssl_sys::wolfSSL_UseKeyShare(
                self.ssl.as_ptr(),
                curve.as_ffi() as wolfssl_sys::word16,
            )
        } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(()),
            wolfssl_sys::wolfCrypt_ErrorCodes_MEMORY_E => panic!("Memory Allocation Failed"),
            e @ wolfssl_sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG => {
                unreachable!("wolfSSL_UseKeyShare: {e:?}")
            }
            e => Err(Error::fatal(e)),
        }
    }

    /// Enable TLS1.3 key logging for applications
    #[cfg(feature = "debug")]
    pub(crate) fn enable_tls13_keylog(&mut self, secret_cb: Tls13SecretCallbacksArg) -> Result<()> {
        self.secret_cb = Some(Box::new(secret_cb));

        let secret_cb: &mut Tls13SecretCallbacksArg = self.secret_cb.as_mut().unwrap();
        let secret_cb: *mut Tls13SecretCallbacksArg = secret_cb as *mut Tls13SecretCallbacksArg;
        let secret_cb = secret_cb as *mut c_void;

        // SAFETY: No documentation available for [`wolfSSL_KeepArrays`].
        // But based on api implementation, it expects a valid pointer
        // to `WOLFSSL`.
        //
        // This implementation is taken from following examples:
        // https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/client-tls13.c
        // https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/server-tls13.c
        unsafe {
            wolfssl_sys::wolfSSL_KeepArrays(self.ssl.as_ptr());
        }

        // SAFETY: No documentation available for [`wolfSSL_set_tls13_secret_cb`].
        // But based on api implementation, it expects a valid pointer
        // to `WOLFSSL`.
        //
        // `secret_cb` is a `Box` pointer so the address is
        // stable. (The address is the address of the heap allocation
        // containing the `Tls13Secretcallbacksarg` which is an `Arc`.
        //
        // We free `self.ssl` (the `wolfssl_sys::WOLFSSL`) on drop of
        // `self`, any use of the callback must have stopped before
        // the drop, since nothing can also be making calls into the session.
        //
        // Therefore `secret_cb` here is valid for as long as it needs to be.
        match unsafe {
            wolfssl_sys::wolfSSL_set_tls13_secret_cb(
                self.ssl.as_ptr(),
                Some(Self::tls13_secret_cb),
                secret_cb,
            )
        } {
            wolfssl_sys::WOLFSSL_SUCCESS_c_int => Ok(()),
            wolfssl_sys::wolfSSL_ErrorCodes_WOLFSSL_FATAL_ERROR => panic!("No SSL context"),
            e => Err(Error::fatal(e)),
        }
    }

    #[cfg(feature = "debug")]
    unsafe extern "C" fn tls13_secret_cb(
        ssl: *mut wolfssl_sys::WOLFSSL,
        id: ::std::os::raw::c_int,
        secret: *const ::std::os::raw::c_uchar,
        secret_size: ::std::os::raw::c_int,
        ctx: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int {
        debug_assert!(!ssl.is_null());
        debug_assert!(!secret.is_null());
        debug_assert!(!ctx.is_null());

        let secret_cb = ctx as *mut Tls13SecretCallbacksArg;
        // SAFETY: We know this pointer is to the contents of the
        // `Box<Tls13SecretCallbacksArg>` at `self.secret_cb` which is
        // owned by the `Session`. See `enable_tls13_keylog` above for
        // an argument to why calls to this callback cannot happen
        // after the `Session` is dropped.
        let secret_cb: &Tls13SecretCallbacksArg = unsafe { &*secret_cb };

        let mut random: Vec<u8> = vec![0; RANDOM_SIZE];
        // SAFETY: We know `ssl` is a valid pointer because we were
        // passed it by wolfssl in the call to this function.
        let get_random = if 1 == unsafe { wolfssl_sys::wolfSSL_is_server(ssl) } {
            wolfssl_sys::wolfSSL_get_server_random
        } else {
            wolfssl_sys::wolfSSL_get_client_random
        };
        // SAFETY: We are calling either [`wolfssl_get_server_random`][0]
        // or [`wolfSSL_get_client_random`][1] as determined
        // above. Both functions have the same requirements.
        //
        // We know `ssl` is a valid pointer because we were passed it
        // by wolfssl in the call to this function.
        //
        // The `out` parameter must be a pointer into a valid buffer
        // of `outlen` bytes, which are satisfied by the `random:
        // Vec<_>` used.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_get_server_random
        // [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_get_client_random
        let random_size =
            unsafe { get_random(ssl, random.as_mut_ptr() as *mut c_uchar, random.len()) };
        if random_size == 0 {
            return 0;
        }
        let random: &[u8] = &random[..random_size];

        // SAFETY:
        //
        // `secret` is a valid pointer from WolfSSL for the duration
        // of the following call to the callback. We trust WolfSSL to
        // give us the correct length.
        //
        // WolfSSL is single threaded so nothing is mutating the
        // buffer under our feet.
        let secret = unsafe { std::slice::from_raw_parts(secret as *mut u8, secret_size as usize) };

        secret_cb.secrets(id.into(), random, secret);

        0
    }
}

impl<IOCB: IOCallbacks> Drop for Session<IOCB> {
    /// Invokes [`wolfSSL_free`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_free
    fn drop(&mut self) {
        // SAFETY: [`wolfSSL_free`][0] ([also][1]) expects a valid pointer to `WOLFSSL`. Per the
        // [Library design][2] access is synchronized via the requirement for `&mut self` in `WolfsslPointer::as_ptr()`.
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_free
        // [1]: https://www.wolfssl.com/doxygen/group__Setup.html#ga640f0a9e17f4727e996fc8bab4eee3c6
        // [2]: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter09.html#thread-safety
        unsafe { wolfssl_sys::wolfSSL_free(self.ssl.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        context::ContextBuilder, Context, Method, RootCertificate, Secret, Session,
        TLS_MAX_RECORD_SIZE,
    };

    use std::rc::Rc;
    use std::sync::{Mutex, OnceLock};

    use test_case::test_case;

    const CA_CERT: &[u8] = &include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/ca_cert_der_2048"
    ));

    const SERVER_CERT: &[u8] = &include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/server_cert_der_2048"
    ));

    const SERVER_KEY: &[u8] = &include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/server_key_der_2048"
    ));

    static INIT_ENV_LOGGER: OnceLock<()> = OnceLock::new();

    // Panics if any I/O is attempted, use for tests where no I/O is expected
    struct NoIOCallbacks;

    impl IOCallbacks for NoIOCallbacks {
        fn recv(&mut self, _buf: &mut [u8]) -> IOCallbackResult<usize> {
            panic!("Unexpected recv on NoIOCallbacks")
        }

        fn send(&mut self, _buf: &[u8]) -> IOCallbackResult<usize> {
            panic!("Unexpected send on NoIOCallbacks")
        }
    }

    struct TestIOCallbacks {
        r: Rc<Mutex<BytesMut>>,
        w: Rc<Mutex<BytesMut>>,
    }

    impl TestIOCallbacks {
        fn pair() -> (Self, Self) {
            let left_to_right = Rc::new(Mutex::new(Default::default()));
            let right_to_left = Rc::new(Mutex::new(Default::default()));

            let left = TestIOCallbacks {
                r: right_to_left.clone(),
                w: left_to_right.clone(),
            };

            let right = TestIOCallbacks {
                r: left_to_right.clone(),
                w: right_to_left.clone(),
            };

            (left, right)
        }
    }

    impl IOCallbacks for TestIOCallbacks {
        fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult<usize> {
            let mut r = self.r.lock().unwrap();
            if r.is_empty() {
                return IOCallbackResult::WouldBlock;
            }

            let n = std::cmp::min(buf.len(), r.len());
            buf[..n].copy_from_slice(&r[..n]);
            r.advance(n);
            IOCallbackResult::Ok(n)
        }

        fn send(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
            let mut w = self.w.lock().unwrap();
            w.extend_from_slice(buf);
            IOCallbackResult::Ok(buf.len()) // extend_from_slice expands w if needed
        }
    }

    struct TestClient {
        _ctx: Context,
        ssl: Session<TestIOCallbacks>,
        read_buffer: Rc<Mutex<BytesMut>>,
        write_buffer: Rc<Mutex<BytesMut>>,
    }

    fn make_connected_clients() -> (TestClient, TestClient) {
        make_connected_clients_with_method(Method::TlsClientV1_3, Method::TlsServerV1_3)
    }

    fn make_connected_clients_with_method(
        client_method: Method,
        server_method: Method,
    ) -> (TestClient, TestClient) {
        let client_ctx = ContextBuilder::new(client_method)
            .unwrap_or_else(|e| panic!("new({client_method:?}): {e}"))
            .with_root_certificate(RootCertificate::Asn1Buffer(CA_CERT))
            .unwrap()
            .with_secure_renegotiation()
            .unwrap()
            .build();

        let server_ctx = ContextBuilder::new(server_method)
            .unwrap_or_else(|e| panic!("new({server_method:?}): {e}"))
            .with_certificate(Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(Secret::Asn1Buffer(SERVER_KEY))
            .unwrap()
            .with_secure_renegotiation()
            .unwrap()
            .build();

        let (client_io, server_io) = TestIOCallbacks::pair();

        let client_read_buffer = client_io.r.clone();
        let client_write_buffer = client_io.w.clone();
        let server_read_buffer = server_io.r.clone();
        let server_write_buffer = server_io.w.clone();

        let client_ssl = client_ctx
            .new_session(SessionConfig::new(client_io))
            .unwrap();
        let server_ssl = server_ctx
            .new_session(SessionConfig::new(server_io))
            .unwrap();

        let mut client = TestClient {
            _ctx: client_ctx,
            ssl: client_ssl,
            read_buffer: client_read_buffer,
            write_buffer: client_write_buffer,
        };

        let mut server = TestClient {
            _ctx: server_ctx,
            ssl: server_ssl,
            read_buffer: server_read_buffer,
            write_buffer: server_write_buffer,
        };

        for _ in 0..7 {
            let _ = client.ssl.try_negotiate().unwrap();
            let _ = server.ssl.try_negotiate().unwrap();
            // Progress is made because one of the above will have
            // written and the other will have PendingRead...
        }

        assert!(client.ssl.is_init_finished());
        assert!(server.ssl.is_init_finished());

        (client, server)
    }

    #[test]
    fn try_negotiate() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        // Internally this calls `try_negotiate`
        let _ = make_connected_clients();
    }

    #[test]
    fn try_write_trivial() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);
        const TEXT: &str = "Hello World";

        let (mut client, _server) = make_connected_clients();

        let mut bytes = BytesMut::from(TEXT.as_bytes());

        // Validate that trivial invocations does not break anything
        match client.ssl.try_write(&mut bytes) {
            Ok(Poll::Ready(n)) => {
                assert!(
                    bytes.is_empty(),
                    "Bytes should have been consumed by WolfSSL"
                );
                assert!(
                    !client.write_buffer.lock().unwrap().is_empty(),
                    "The write buffer should be populated as a result"
                );
                assert!(
                    client.read_buffer.lock().unwrap().is_empty(),
                    "The read buffer should _not_ be populated as a result"
                );
                assert_eq!(
                    n,
                    TEXT.len(),
                    "The number of bytes reported to be written should match"
                );
            }
            x => {
                panic!("Expected bytes to be written! Got {x:?}")
            }
        }
    }

    // Passing in 0 counterintutively results in a WANT_READ/WANT_WRITE instead of an ERROR_NONE
    #[test_case(0 => panics)]
    #[test_case("Hello World".len() => "Hello World".len())]
    #[test_case(TLS_MAX_RECORD_SIZE - 1 => TLS_MAX_RECORD_SIZE - 1)]
    // More than one invocation to `try_read`/`try_write` would be required here
    #[test_case(TLS_MAX_RECORD_SIZE => panics)]
    fn try_read_and_write_roundtrip_once(len: usize) -> usize {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let text = "A".repeat(len);

        let (mut client, mut server) = make_connected_clients();

        let mut client_bytes = BytesMut::from(text.as_bytes());

        assert_eq!(client_bytes.capacity(), len);

        let Ok(Poll::Ready(_)) = client.ssl.try_write(&mut client_bytes) else {
            panic!("Unusual write behavior for this payload");
        };

        let mut server_bytes = BytesMut::with_capacity(text.len());

        match server.ssl.try_read(&mut server_bytes) {
            Ok(Poll::Ready(n)) => {
                let read_result = String::from_utf8_lossy(&server_bytes);

                assert_eq!(n, text.len());
                assert_eq!(read_result, text);

                n
            }
            e => panic!("Expected bytes to be read! Got {e:?}"),
        }
    }

    #[test]
    fn try_rehandshake() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let (mut client, mut server) =
            make_connected_clients_with_method(Method::DtlsClientV1_2, Method::DtlsServerV1_2);

        assert!(client.ssl.is_secure_renegotiation_supported());
        assert!(server.ssl.is_secure_renegotiation_supported());

        const TEST: &str = "foobar";

        for _ in 0..5 {
            let mut bytes = BytesMut::from(TEST.as_bytes());

            // Keep invoking `try_rehandshake` to progress the secure
            // renegotiation.
            match client.ssl.try_rehandshake() {
                Ok(Poll::Ready(_)) => {
                    break;
                }
                Ok(Poll::PendingRead | Poll::PendingWrite) => {}
                Ok(Poll::AppData(_)) => {
                    panic!("Should not receive AppData from anywhere")
                }
                Err(e) => panic!("{e}"),
            }

            // While we are here, also test out the Application Data
            // functionality. Lets send some app data while a secure
            // renegotiation is ongoing.
            match client.ssl.try_write(&mut bytes) {
                Ok(Poll::Ready(_) | Poll::PendingRead | Poll::PendingWrite) => {}
                Ok(Poll::AppData(_)) => {
                    panic!("Should not receive AppData from anywhere")
                }
                Err(e) => panic!("{e}"),
            };

            // We should expect to see on the server side that some application
            // data has been discovered, and that we should get it out or
            // otherwise lose it.
            let mut server_bytes = BytesMut::with_capacity(TEST.len());
            match server.ssl.try_read(&mut server_bytes) {
                Ok(Poll::Ready(_) | Poll::PendingRead | Poll::PendingWrite) => {}
                Ok(Poll::AppData(b)) => {
                    assert_eq!(b, TEST);
                    // `server_bytes` should not have been modified if appdata
                    // is discovered.
                    assert!(server_bytes.is_empty());
                }
                Err(e) => panic!("{e}"),
            };
        }

        assert!(!client.ssl.is_secure_renegotiation_pending());
        assert!(!server.ssl.is_secure_renegotiation_pending());
    }

    #[test_case(Method::TlsClientV1_3, Method::TlsServerV1_3; "tls1.3")]
    #[test_case(Method::DtlsClientV1_3, Method::DtlsServerV1_3; "dtls1.3")]
    fn try_trigger_update_keys(client: Method, server: Method) {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let (mut client, mut server) = make_connected_clients_with_method(client, server);

        assert!(client.ssl.version().is_tls_13() || client.ssl.version().is_dtls_13());
        assert!(server.ssl.version().is_tls_13() || server.ssl.version().is_dtls_13());

        // Trigger the wolfssl key update mechanism. This will cause the client
        // to send a key update message.
        match client.ssl.try_trigger_update_key() {
            Ok(Poll::Ready(_)) => {}
            Ok(Poll::PendingRead | Poll::PendingWrite) => {
                panic!("Should not be pending any data")
            }
            Ok(Poll::AppData(_)) => {
                panic!("Should not receive AppData from anywhere")
            }
            Err(e) => panic!("{e}"),
        }

        assert!(
            client.ssl.is_update_keys_pending(),
            "Client should be expecting a response containing decryption keys"
        );

        // The server reads no application data, but this internally triggers
        // some wolfSSL machinery to deal with the key update.
        //
        // This will cause the server to send its own key update message.
        match server.ssl.try_read(&mut BytesMut::with_capacity(0)) {
            Ok(Poll::PendingRead) => {}
            Ok(Poll::PendingWrite) => panic!("Should be nothing to write"),
            Ok(Poll::Ready(_)) => {
                panic!("There should be no data to read")
            }
            Ok(Poll::AppData(_)) => {
                panic!("Should not receive AppData from anywhere");
            }
            Err(e) => panic!("{e}"),
        };

        // The client also reads no application data, but this will trigger the
        // same key update machinery to occur on the client side.
        match client.ssl.try_read(&mut BytesMut::with_capacity(0)) {
            Ok(Poll::PendingRead) => {}
            Ok(Poll::PendingWrite) => panic!("Should be nothing to write"),
            Ok(Poll::Ready(_)) => {
                panic!("There should be no data to read")
            }
            Ok(Poll::AppData(_)) => {
                panic!("Should not receive AppData from anywhere")
            }
            Err(e) => panic!("{e}"),
        };

        assert!(
            !client.ssl.is_update_keys_pending(),
            "Key update should be done within one round trip"
        );
    }

    #[test]
    fn dtls_current_timeout() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let client_ctx = ContextBuilder::new(Method::DtlsClientV1_2).unwrap().build();

        let mut ssl = client_ctx
            .new_session(SessionConfig::new(NoIOCallbacks))
            .unwrap();

        // The default is 1 second (`DTLS_TIMEOUT_INIT`). This might change in
        // the future or at the whims of the WolfSSL library authors
        assert_eq!(
            ssl.dtls_current_timeout(),
            std::time::Duration::from_secs(1)
        );
    }

    #[test_case(true)]
    // TODO (pangt): Unable to force a time-in. I'm not sure if the test is
    // constructed wrongly, or if it's something else.
    #[test_case(false => ignore)]
    fn dtls_timeout(should_timeout: bool) {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let (mut client, _server) =
            make_connected_clients_with_method(Method::DtlsClientV1_2, Method::DtlsServerV1_2);

        client
            .ssl
            .dtls_set_max_timeout(Duration::from_secs(2))
            .unwrap();
        client.ssl.dtls_set_timeout(Duration::from_secs(2)).unwrap();

        // Force a duration that must cause a timeout.
        let curr_timeout = client.ssl.dtls_current_timeout();
        let dtls_timeout = if should_timeout {
            let d = Duration::from_secs(3);
            assert!(d > curr_timeout);
            d
        } else {
            let d = Duration::from_secs(1);
            assert!(d < curr_timeout);
            d
        };

        // Initiate something that requires a handshake
        match client.ssl.try_rehandshake() {
            Ok(Poll::Ready(_) | Poll::PendingRead | Poll::PendingWrite) => {}
            e => panic!("{e:?}"),
        }

        std::thread::sleep(dtls_timeout);

        // Ask for a handshake again.
        match client.ssl.try_rehandshake() {
            Ok(Poll::Ready(_) | Poll::PendingRead | Poll::PendingWrite) => {}
            e => panic!("{e:?}"),
        }

        // This should have timed out since no reply has been returned
        // (deliberately) past the timeout period.
        let res = match client.ssl.dtls_has_timed_out() {
            Poll::Ready(x) => x,
            e => panic!("{e:?}"),
        };

        assert_eq!(should_timeout, res);
    }

    #[test_case(0)]
    #[test_case(1)]
    #[test_case(10)]
    #[test_case(2u16.pow(14))]
    #[test_case(2u16.pow(14) + 1)]
    fn dtls_mtu(mtu: u16) {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let client_ctx = ContextBuilder::new(Method::DtlsClientV1_2).unwrap().build();

        let mut ssl = client_ctx
            .new_session(SessionConfig::new(NoIOCallbacks))
            .unwrap();

        ssl.dtls_set_mtu(mtu);
    }

    #[test]
    fn dtls13_use_quick_timeout() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        // call before connection
        let client_ctx = ContextBuilder::new(Method::DtlsClientV1_3).unwrap().build();

        let mut ssl = client_ctx
            .new_session(SessionConfig::new(NoIOCallbacks))
            .unwrap();

        assert!(!ssl.dtls13_use_quick_timeout());

        // call after connection succeeds
        let (mut client, _) = make_connected_clients();
        assert!(!client.ssl.dtls13_use_quick_timeout());
    }

    #[test_case(true)]
    #[test_case(false)]
    fn dtls13_allow_ch_frag(allow: bool) {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        // call before connection
        let server_ctx = ContextBuilder::new(Method::DtlsServerV1_3)
            .unwrap()
            .with_certificate(Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(Secret::Asn1Buffer(SERVER_KEY))
            .unwrap()
            .build();

        let mut ssl = server_ctx
            .new_session(SessionConfig::new(NoIOCallbacks))
            .unwrap();

        ssl.dtls13_allow_ch_frag(allow).expect("ok");
    }

    #[test]
    fn get_current_cipher_name() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let (mut client, mut server) = make_connected_clients();

        // Both should have a cipher and both should be the same
        // cipher.
        assert_eq!(
            client.ssl.get_current_cipher_name().unwrap(),
            server.ssl.get_current_cipher_name().unwrap()
        )
    }

    #[test]
    fn get_current_curve_name() {
        INIT_ENV_LOGGER.get_or_init(env_logger::init);

        let (mut client, mut server) = make_connected_clients();

        // Both should have a curve and both should be the same
        // curve.
        assert_eq!(
            dbg!(client.ssl.get_current_curve_name().unwrap()),
            dbg!(server.ssl.get_current_curve_name().unwrap())
        )
    }

    #[test_case(SslVerifyMode::SslVerifyNone, SslVerifyMode::SslVerifyNone)]
    #[test_case(SslVerifyMode::SslVerifyNone, SslVerifyMode::SslVerifyPeer => panics "ASN no signer error to confirm failure")]
    #[test_case(SslVerifyMode::SslVerifyPeer, SslVerifyMode::SslVerifyNone)]
    #[test_case(SslVerifyMode::SslVerifyPeer, SslVerifyMode::SslVerifyPeer => panics "ASN no signer error to confirm failure")]
    #[test_case(SslVerifyMode::SslVerifyFailIfNoPeerCert, SslVerifyMode::SslVerifyNone => panics "peer did not return a certificate")]
    #[test_case(SslVerifyMode::SslVerifyFailIfNoPeerCert, SslVerifyMode::SslVerifyPeer => panics "ASN no signer error to confirm failure")]
    #[test_case(SslVerifyMode::SslVerifyFailExceptPsk, SslVerifyMode::SslVerifyNone)]
    #[test_case(SslVerifyMode::SslVerifyFailExceptPsk, SslVerifyMode::SslVerifyPeer => panics "ASN no signer error to confirm failure")]
    fn test_client_set_verify(server_mode: SslVerifyMode, client_mode: SslVerifyMode) {
        let client_method = Method::TlsClientV1_3;
        // Create context without server CA certificate
        let client_ctx = ContextBuilder::new(client_method)
            .unwrap_or_else(|e| panic!("new({client_method:?}): {e}"))
            .with_secure_renegotiation()
            .unwrap()
            .build();

        let server_method = Method::TlsServerV1_3;
        let server_ctx = ContextBuilder::new(server_method)
            .unwrap_or_else(|e| panic!("new({server_method:?}): {e}"))
            .with_certificate(Secret::Asn1Buffer(SERVER_CERT))
            .unwrap()
            .with_private_key(Secret::Asn1Buffer(SERVER_KEY))
            .unwrap()
            .with_secure_renegotiation()
            .unwrap()
            .build();

        let (client_io, server_io) = TestIOCallbacks::pair();

        let mut client_ssl = client_ctx
            .new_session(SessionConfig::new(client_io).with_ssl_verify_mode(client_mode))
            .unwrap();
        let mut server_ssl = server_ctx
            .new_session(SessionConfig::new(server_io).with_ssl_verify_mode(server_mode))
            .unwrap();

        for _ in 0..7 {
            let _ = client_ssl.try_negotiate().unwrap();
            let _ = server_ssl.try_negotiate().unwrap();
        }

        assert!(client_ssl.is_init_finished());
        assert!(server_ssl.is_init_finished());
    }
}
