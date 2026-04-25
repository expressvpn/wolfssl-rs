use std::mem::MaybeUninit;

use bytes::BytesMut;
use thiserror::Error;
use wolfssl_sys::{
    wc_AesFree, wc_AesGcmDecrypt, wc_AesGcmEncrypt, wc_AesGcmSetKey, wc_AesInit, Aes, INVALID_DEVID,
};

use crate::ErrorKind;

#[derive(Error, Debug)]
/// The failure result of an operation.
pub enum Aes256GcmError {
    /// Aes init failed
    #[error("Aes Init Failed ")]
    AesInitFailed,

    /// Invalid key
    #[error("Invalid key")]
    InvalidKey,

    /// Top-level errors from WolfSSL API invocations.
    #[error("Fatal: {0}")]
    Fatal(ErrorKind),
}

/// Struct for encrypt/decrypt using Aes256Gcm cipher
pub struct Aes256Gcm {
    aes: Box<Aes>,
    valid_key: bool,
}

/// Safety: Aes256Gcm is safe to Send between threads because:
/// - Each instance owns its WolfSSL Aes context completely (`Box<Aes>`)
/// - The underlying Aes structure contains only per-instance cryptographic state
/// - No shared mutable state exists between different Aes256Gcm instances
/// - WolfSSL is built with single-threaded mode, placing thread synchronization
///   responsibility on the application (which Rust's ownership system handles)
unsafe impl Send for Aes256Gcm {}

/// Safety: Aes256Gcm is safe to Sync (concurrent access from multiple threads) because:
/// - Each Aes256Gcm instance maintains completely separate cryptographic state
/// - The underlying WolfSSL Aes structure has no internal shared mutable state
/// - Concurrent access means multiple threads each using their own Aes256Gcm instance,
///   not multiple threads accessing the same instance (which &mut self prevents)
unsafe impl Sync for Aes256Gcm {}

impl Aes256Gcm {
    /// Size of key
    pub const KEY_SIZE: usize = wolfssl_sys::AES_256_KEY_SIZE as usize;

    /// Size of Initialisation vector
    pub const IV_SIZE: usize = 12;

    /// Size of auth tag
    pub const AUTHTAG_SIZE: usize = 16;

    /// Creates new `Aes256Gcm`
    pub fn new() -> Result<Self, Aes256GcmError> {
        let mut aes = Box::new(MaybeUninit::<Aes>::uninit());

        // SAFETY: [`wc_AesInit`] have the following requirements from:
        // https://www.wolfssl.com/documentation/manuals/wolfssl/aes_8h.html#function-wc_aesinit
        //
        // First argument `aes` structure should be valid mutable pointer pointing to `Aes`
        // We create a Uninit memory and then sending the mutable pointer to satisfy it.
        let aes_init_status =
            unsafe { wc_AesInit(aes.as_mut_ptr(), std::ptr::null_mut(), INVALID_DEVID) };
        if aes_init_status != 0 {
            return Err(Aes256GcmError::AesInitFailed);
        };

        // SAFETY: Since [`wc_AesInit`][0] api returns successfully with 0, memory pointed
        // by `aes` is now valid
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/aes_8h.html#function-wc_aesinit
        let aes = unsafe { aes.assume_init() };

        // Since aes is init'ed, safe to construct AesProtected
        Ok(Aes256Gcm {
            aes,
            valid_key: false,
        })
    }

    /// Set key for Aes256Gcm cipher
    pub fn set_key(&mut self, key: [u8; Aes256Gcm::KEY_SIZE]) -> Result<(), Aes256GcmError> {
        // SAFETY: aes is already initialized by new()
        let ret = unsafe {
            wc_AesGcmSetKey(
                self.aes.as_mut(),
                key.as_ptr(),
                key.len() as wolfssl_sys::word32,
            )
        };
        if ret != 0 {
            return Err(Aes256GcmError::Fatal(ErrorKind::from(ret)));
        }
        self.valid_key = true;
        Ok(())
    }

    /// This function encrypts an input message `plain_text`, using AES-GCM cipher,
    /// It also performs additional authentication (on the cipher text),
    /// and stores the generated authentication tag in the output buffer
    pub fn encrypt(
        &mut self,
        iv: [u8; Aes256Gcm::IV_SIZE],
        plain_text: &[u8],
        auth_vec: &[u8],
    ) -> Result<(BytesMut, [u8; Aes256Gcm::AUTHTAG_SIZE]), Aes256GcmError> {
        if !self.valid_key {
            return Err(Aes256GcmError::InvalidKey);
        }

        let mut cipher_text = BytesMut::with_capacity(plain_text.len());
        let mut auth_tag = [0u8; Aes256Gcm::AUTHTAG_SIZE];

        // SAFETY: [`wc_AesGcmEncrypt`][0] have the following requirements:
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html#function-wc_aesgcmencrypt
        match unsafe {
            wc_AesGcmEncrypt(
                self.aes.as_mut(),
                cipher_text.as_mut_ptr(),
                plain_text.as_ptr(),
                plain_text.len() as u32,
                iv.as_ptr(),
                Aes256Gcm::IV_SIZE as u32,
                auth_tag.as_mut_ptr(),
                auth_tag.len() as u32,
                auth_vec.as_ptr(),
                auth_vec.len() as u32,
            )
        } {
            0 => {
                // SAFETY: Now that we've initialized this memory segment, it is safe to update the
                // length to account for the initialized data
                unsafe {
                    cipher_text.set_len(plain_text.len());
                }
                Ok((cipher_text, auth_tag))
            }
            ret => Err(Aes256GcmError::Fatal(ErrorKind::from(ret))),
        }
    }

    /// This function decrypts input `cipher_text`, using the Aes256Gcm block cipher.
    pub fn decrypt(
        &mut self,
        iv: [u8; Aes256Gcm::IV_SIZE],
        cipher_text: &[u8],
        auth_vec: &[u8],
        auth_tag: &[u8; Aes256Gcm::AUTHTAG_SIZE],
    ) -> Result<BytesMut, Aes256GcmError> {
        if !self.valid_key {
            return Err(Aes256GcmError::InvalidKey);
        }

        let mut plain_text = BytesMut::with_capacity(cipher_text.len());

        // SAFETY: [`wc_AesGcmDecrypt`][0] have the following requirements:
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html#function-wc_aesgcmdecrypt
        match unsafe {
            wc_AesGcmDecrypt(
                self.aes.as_mut(),
                plain_text.as_mut_ptr(),
                cipher_text.as_ptr(),
                cipher_text.len() as u32,
                iv.as_ptr(),
                Aes256Gcm::IV_SIZE as u32,
                auth_tag.as_ptr(),
                auth_tag.len() as u32,
                auth_vec.as_ptr(),
                auth_vec.len() as u32,
            )
        } {
            0 => {
                // SAFETY: Now that we've initialized this memory segment, it is safe to update the
                // length to account for the initialized data
                unsafe {
                    plain_text.set_len(cipher_text.len());
                }
                Ok(plain_text)
            }
            ret => Err(Aes256GcmError::Fatal(ErrorKind::from(ret))),
        }
    }
}

impl Drop for Aes256Gcm {
    fn drop(&mut self) {
        // SAFETY: Based on [`wc_AesFree`][0], the argument should be valid Aes Struct
        // initialized by `wc_AesInit`
        //
        // Since we contruct AesProtected only after `wc_AesInit` call, safe to call `wc_AesFree`
        //
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/aes_8h.html#function-wc_aesfree
        unsafe {
            wc_AesFree(self.aes.as_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Aes256GcmError;

    use super::{Aes, Aes256Gcm};

    const KEY: [u8; Aes256Gcm::KEY_SIZE] = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83,
        0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
        0x83, 0x08,
    ];
    const PLAIN_TEXT: [u8; 60] = [
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26,
        0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
        0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
        0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
    ];
    const IV: [u8; Aes256Gcm::IV_SIZE] = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
    ];
    const AUTH_VEC: &[u8] = &[
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
        0xef, 0xab, 0xad, 0xda, 0xd2,
    ];
    const CIPHER_TEXT: [u8; 60] = [
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42,
        0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55,
        0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56,
        0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62,
    ];
    const EXP_AUTH_TAG: &[u8; Aes256Gcm::AUTHTAG_SIZE] = &[
        0x76, 0xfc, 0x6e, 0xce, 0xf, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55,
        0x1b,
    ];

    #[test]
    fn test_aes_size() {
        cfg_if::cfg_if! {
            if #[cfg(not(windows))] {
                assert_eq!(std::mem::size_of::<Aes>(), 123728);
            } else if #[cfg(all(windows, target_arch = "aarch64"))] {
                assert_eq!(std::mem::size_of::<Aes>(), 320);
            } else {
                // Non-arm64 windows
                assert_eq!(std::mem::size_of::<Aes>(), 336);
            }
        }
        assert_eq!(std::mem::size_of::<Aes256Gcm>(), 16);
    }

    #[test]
    fn test_aes256gcm() {
        let _ = Aes256Gcm::new().unwrap();
    }

    #[test]
    fn test_aes256gcm_encrypt() {
        let mut cipher = Aes256Gcm::new().unwrap();
        cipher.set_key(KEY).unwrap();

        let (cipher_text, auth_tag) = cipher.encrypt(IV, &PLAIN_TEXT, AUTH_VEC).unwrap();
        assert_eq!(&cipher_text[..], &CIPHER_TEXT);
        assert_eq!(&auth_tag[..], &EXP_AUTH_TAG[..]);
    }

    #[test]
    fn test_aes256gcm_encrypt_wo_key() {
        let mut cipher = Aes256Gcm::new().unwrap();
        let res = cipher.encrypt(IV, &PLAIN_TEXT, AUTH_VEC);
        assert!(matches!(res, Err(Aes256GcmError::InvalidKey)));
    }

    #[test]
    fn test_aes256gcm_decrypt_wo_key() {
        let mut cipher = Aes256Gcm::new().unwrap();
        let res = cipher.decrypt(IV, CIPHER_TEXT.as_ref(), AUTH_VEC, EXP_AUTH_TAG);
        assert!(matches!(res, Err(Aes256GcmError::InvalidKey)));
    }

    #[test]
    fn test_aes256gcm_decrypt() {
        let mut cipher = Aes256Gcm::new().unwrap();
        cipher.set_key(KEY).unwrap();

        let plaint_text = cipher
            .decrypt(IV, CIPHER_TEXT.as_ref(), AUTH_VEC, EXP_AUTH_TAG)
            .unwrap();
        assert_eq!(&plaint_text[..], &PLAIN_TEXT);
    }
}
