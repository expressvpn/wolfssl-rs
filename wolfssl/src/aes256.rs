use std::mem::MaybeUninit;

use bytes::BytesMut;
use wolfssl_sys::{
    wc_AesGcmDecrypt, wc_AesGcmEncrypt, wc_AesGcmSetKey, wc_AesInit, Aes, INVALID_DEVID,
};

/// Struct for encrypt/decrypt using Aes256Gcm cipher
pub struct Aes256Gcm {
    enc: Aes,
    dec: Aes,
}

impl Aes256Gcm {
    /// Size of Initialisation vector
    pub const IV_SIZE: usize = wolfssl_sys::WOLFSSL_MIN_AUTH_TAG_SZ as usize;

    /// Size of key
    pub const KEY_SIZE: usize = wolfssl_sys::AES_256_KEY_SIZE as usize;

    /// Size of auth tag
    pub const AUTHTAG_SIZE: usize = wolfssl_sys::AES_BLOCK_SIZE as usize;

    /// Creates new `Aes256
    pub fn new(key: [u8; Self::KEY_SIZE]) -> Self {
        let mut enc = MaybeUninit::<Aes>::uninit();
        let mut dec = MaybeUninit::<Aes>::uninit();

        #[allow(clippy::multiple_unsafe_ops_per_block)]
        #[allow(clippy::undocumented_unsafe_blocks)]
        let (mut enc, mut dec) = unsafe {
            wc_AesInit(enc.as_mut_ptr(), std::ptr::null_mut(), INVALID_DEVID);
            wc_AesInit(dec.as_mut_ptr(), std::ptr::null_mut(), INVALID_DEVID);
            (enc.assume_init(), dec.assume_init())
        };

        // SAFETY: enc is already initialized
        unsafe {
            wc_AesGcmSetKey(&mut enc, key.as_ptr(), key.len() as u32);
        }

        // SAFETY: dec is already initialized
        unsafe {
            wc_AesGcmSetKey(&mut dec, key.as_ptr(), key.len() as wolfssl_sys::word32);
        }

        Self { enc, dec }
    }

    /// This function encrypts an input message `plain_text`, using the ChaCha20 stream cipher,
    /// It also performs Poly-1305 authentication (on the cipher text),
    /// and stores the generated authentication tag in the output buffer
    pub fn encrypt(
        &mut self,
        iv: [u8; Self::IV_SIZE],
        plain_text: &[u8],
        auth_vec: &[u8],
    ) -> Result<(BytesMut, [u8; Self::AUTHTAG_SIZE]), String> {
        let mut cipher_text = BytesMut::with_capacity(plain_text.len());
        let mut auth_tag = [0u8; Self::AUTHTAG_SIZE];

        // SAFETY: [`wc_AesGcmEncrypt`][0] have the following requirements:
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html#function-wc_aesgcmencrypt
        match unsafe {
            wc_AesGcmEncrypt(
                &mut self.dec,
                cipher_text.as_mut_ptr(),
                plain_text.as_ptr(),
                plain_text.len() as u32,
                iv.as_ptr(),
                Self::IV_SIZE as u32,
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
            _ => Err(String::from("Encrypt failed")),
        }
    }

    /// This function decrypts input `cipher_text`, using the Aes256Gcm block cipher.
    pub fn decrypt(
        &mut self,
        iv: [u8; Self::IV_SIZE],
        cipher_text: &[u8],
        auth_vec: &[u8],
        auth_tag: &[u8; Self::AUTHTAG_SIZE],
    ) -> Result<BytesMut, String> {
        let mut plain_text = BytesMut::with_capacity(cipher_text.len());

        // SAFETY: [`wc_AesGcmDecrypt`][0] have the following requirements:
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html#function-wc_aesgcmdecrypt
        match unsafe {
            wc_AesGcmDecrypt(
                &mut self.enc,
                plain_text.as_mut_ptr(),
                cipher_text.as_ptr(),
                cipher_text.len() as u32,
                iv.as_ptr(),
                Self::IV_SIZE as u32,
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
            _ => Err(String::from("Decrypt failed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Aes256Gcm;

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

    #[test]
    fn test_aes256gcm_encrypt() -> Result<(), String> {
        let mut cipher = Aes256Gcm::new(KEY);

        let (cipher_text, auth_tag) = cipher.encrypt(IV, &PLAIN_TEXT, AUTH_VEC).unwrap();
        assert_eq!(&cipher_text[..], &CIPHER_TEXT);

        let plaint_text = cipher
            .decrypt(IV, cipher_text.as_ref(), AUTH_VEC, &auth_tag)
            .unwrap();
        assert_eq!(&plaint_text[..], &PLAIN_TEXT);
        Ok(())
    }

    // #[test]
    // fn test_chacha20_decrypt() -> Result<(), String> {
    //     let cipher = Aes256Gcm::new(KEY);
    //     let plaint_text = cipher.decrypt(IV, &CIPHER_TEXT, AUTH_TAG).unwrap();
    //     assert_eq!(&plaint_text[..], &PLAIN_TEXT);
    //     Ok(())
    // }
}
