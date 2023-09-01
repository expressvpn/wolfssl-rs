/// Result type to be returned by methods on [`IOCallbacks`]
#[derive(Debug)]
pub enum IOCallbackResult<T> {
    /// Success
    Ok(T),
    /// The I/O operation would block, this will surface to the
    /// application as [`crate::Poll::PendingRead`] or [`crate::Poll::PendingWrite`]
    WouldBlock,
    /// Any other error
    Err(std::io::Error),
}

/// The application provided IO callbacks documented at
/// [`EmbedRecieve`][0] (whose inputs and outputs we need to
/// emulate). See also [`wolfSSL_CTX_SetIORecv`][0] which is the best
/// docs for `wolfSSL_CTX_SetIORecv` and `wolfSSL_CTX_SetIOSend`,
/// which are what we actually use.
///
/// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-embedreceive
/// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/wolfio_8h.html#function-wolfssl_ctx_setiorecv
pub trait IOCallbacks {
    /// Called when WolfSSL wishes to receive some data.
    ///
    /// Receive as many bytes as possible into provided buffer, return
    /// the number of bytes actually received. If the operation would
    /// block [`std::io::ErrorKind::WouldBlock`] then return
    /// [`IOCallbackResult::WouldBlock`].
    fn recv(&self, buf: &mut [u8]) -> IOCallbackResult<usize>;

    /// Called when WolfSSL wishes to send some data
    ///
    /// Send as many bytes as possible from the provided buffer,
    /// return the number of bytes actually consumed. If the operation would
    /// block [`std::io::ErrorKind::WouldBlock`] then return
    /// [`IOCallbackResult::WouldBlock`].
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize>;
}
