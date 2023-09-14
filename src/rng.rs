use crate::error::{Error, Result};

/// Provides a way to extract random values from WolfSSL.
pub struct Random(wolfssl_sys::WC_RNG);

impl Random {
    /// Initializes a [`Random`] object.
    pub fn new() -> Result<Random> {
        crate::wolf_init()?;

        let mut rng = std::mem::MaybeUninit::<wolfssl_sys::WC_RNG>::uninit();
        // SAFETY:
        // [`wc_InitRng()`][0] ([also][1]) is documented to receive [`WC_RNG`] as input to initialise seed and key cipher.
        // The corresponding memory is deallocated, when dropping this structure
        //
        // [0]: https://www.wolfssl.com/doxygen/group__Random.html#ga1a87307fac65d3c2a47ffb743020f83c
        // [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Random.html#function-wc_initrng
        match unsafe { wolfssl_sys::wc_InitRng(rng.as_mut_ptr()) } {
            0 => {
                // SAFETY:
                // Based on the documentation from [`wc_InitRng()`][0], `rng` will be initialised successfully
                // if the return code is `0`. So can safely call `assume_init` here
                //
                // [0]: https://www.wolfssl.com/doxygen/group__Random.html#ga1a87307fac65d3c2a47ffb743020f83c
                let rng = unsafe { rng.assume_init() };
                Ok(Random(rng))
            }
            e => Err(Error::fatal(e)),
        }
    }

    /// Generates a random u64. Advances the internal state of the RNG.
    pub fn random_u64(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        // SAFETY:
        // The following invariants required by [`wc_RNG_GenerateBlock()`][0] is satisfied:
        //      - first argument `&rng` is mutable reference to properly initialised random number generator
        //      - second argment has valid mutable buffer with proper size corresponding to the size `sz`
        //
        // [0]: https://www.wolfssl.com/doxygen/group__Random.html#ga9a289fb3f58f4a5f7e15c2b5a1b0d7c6
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
        // SAFETY:
        // [`wc_FreeRng()`][0] receives properly initialised random number generator [`WC_RNG`] as input to securely free drgb.
        // The pointer used as argument is created by `wc_InitRng` api call in new() constructor.
        //
        // [0]: https://www.wolfssl.com/doxygen/group__Random.html#ga72ffd8b507b3a895af8a6e9996caba86
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
