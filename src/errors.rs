/// Return error values for [`wolf_init`]
#[derive(Debug)]
pub enum WolfInitError {
    /// Corresponds with `BAD_MUTEX_E`
    Mutex,
    /// Corresponds with `WC_INIT_E`
    WolfCrypt,
}

/// Return error values for [`wolf_cleanup`]
#[derive(Debug)]
pub enum WolfCleanupError {
    /// Corresponds with `BAD_MUTEX_E`
    Mutex,
}
