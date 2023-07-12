use crate::error::{Error, Result};

/// Provides a way to extract random values from WolfSSL.
pub struct Random(wolfssl_sys::WC_RNG);

impl Random {
    /// Initializes a [`Random`] object.
    pub fn new() -> Result<Random> {
        let mut rng = std::mem::MaybeUninit::<wolfssl_sys::WC_RNG>::uninit();
        match unsafe { wolfssl_sys::wc_InitRng(rng.as_mut_ptr()) } {
            0 => {
                let rng = unsafe { rng.assume_init() };
                Ok(Random(rng))
            }
            e => Err(Error::fatal(e)),
        }
    }

    /// Generates a random u64. Advances the internal state of the RNG.
    pub fn random_u64(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        match unsafe {
            wolfssl_sys::wc_RNG_GenerateBlock(&mut self.0 as *mut _, buf.as_mut_ptr(), 8)
        } {
            0 => Ok(u64::from_ne_bytes(buf)),
            e => Err(Error::fatal(e)),
        }
    }
}

impl Drop for Random {
    fn drop(&mut self) {
        let res = unsafe { wolfssl_sys::wc_FreeRng(&mut self.0 as *mut _) };

        if res != 0 {
            log::warn!("Unusual free result: {}", Error::fatal(res));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_roundtrip() {
        let mut rng = Random::new().unwrap();

        for _ in 0..10 {
            let _ = rng.random_u64().unwrap();
        }

        drop(rng)
    }
}
