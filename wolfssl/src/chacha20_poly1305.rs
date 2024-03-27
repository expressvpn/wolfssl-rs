use bytes::BytesMut;
use wolfssl_sys::{wc_ChaCha20Poly1305_Decrypt, wc_ChaCha20Poly1305_Encrypt};

/// Struct for encrypt/decrypt using Chacha20 cipher and authentication
/// using Poly1305
pub struct Chacha20Poly1305Aead {
    key: [u8; Self::KEY_SIZE],
}

impl Chacha20Poly1305Aead {
    /// Size of Initialisation vector
    pub const IV_SIZE: usize = wolfssl_sys::CHACHA20_POLY1305_AEAD_IV_SIZE as usize;

    /// Size of key
    pub const KEY_SIZE: usize = wolfssl_sys::CHACHA20_POLY1305_AEAD_KEYSIZE as usize;

    /// Size of auth tag
    pub const AUTHTAG_SIZE: usize = wolfssl_sys::CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE as usize;

    /// Creates new `Chacha20Poly1305Aead` instance
    pub fn new(key: [u8; Self::KEY_SIZE]) -> Self {
        Self { key }
    }

    /// This function encrypts an input message `plain_text`, using the ChaCha20 stream cipher,
    /// It also performs Poly-1305 authentication (on the cipher text),
    /// and stores the generated authentication tag in the output buffer
    pub fn encrypt(
        &self,
        iv: [u8; Self::IV_SIZE],
        plain_text: &[u8],
    ) -> Result<(BytesMut, [u8; Self::AUTHTAG_SIZE]), String> {
        let mut cipher_text = BytesMut::with_capacity(plain_text.len());
        let mut auth_tag = [0u8; Self::AUTHTAG_SIZE];

        // SAFETY: [`wc_ChaCha20Poly1305_Encrypt`][0] have the following requirements:
        // - `inKey` should be a valid pointer with size `wolfssl::CHACHA20_POLY1305_AEAD_KEYSIZE`
        // - `inIv` should be a valid pointer with size `wolfssl::CHACHA20_POLY1305_AEAD_IV_SIZE`
        // - `outAuthTag` should be a valid mutable pointer with size equal to `wolfssl::CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE`
        // - `inAAD` should be a valid pointer with size equal to `inAADLen`
        // - `inPlaintext` should be a valid pointer with size equal to `inPlaintextLen`
        // - `outCipherText` should be a valid mutable pointer with size equal to `inPlaintextLen`
        //
        // First three invariants are maintained using byteslice of respective sizes.
        // We do not use `inAAD`, hence it is null and 0.
        // `inPlaintext` is again a byteslice and `inPlaintextLen` is using len() of bytesslice
        // `outCipherText` we are creating a new BytesMut with same capacity as `inPlaintext` explicitly
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/chacha20__poly1305_8h.html#function-wc_chacha20poly1305_encrypt
        match unsafe {
            wc_ChaCha20Poly1305_Encrypt(
                self.key.as_ptr(),
                iv.as_ptr(),
                std::ptr::null(),
                0,
                plain_text.as_ptr(),
                plain_text.len() as u32,
                cipher_text.spare_capacity_mut().as_mut_ptr() as *mut u8,
                auth_tag.as_mut_ptr(),
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

    /// This function decrypts input `cipher_text`, using the ChaCha20 stream cipher.
    /// It also performs Poly-1305 authentication, comparing the given inAuthTag to
    /// an authentication generated with the inAAD (arbitrary length additional authentication data).
    /// Note: If the generated authentication tag does not match the supplied authentication tag,
    /// the text is not decrypted.
    pub fn decrypt(
        &self,
        iv: [u8; Self::IV_SIZE],
        cipher_text: &[u8],
        auth_tag: [u8; Self::AUTHTAG_SIZE],
    ) -> Result<BytesMut, String> {
        let mut plain_text = BytesMut::with_capacity(cipher_text.len());

        // SAFETY: [`wc_ChaCha20Poly1305_Decrypt`][0] have the following requirements:
        // - `inKey` should be a valid pointer with size `wolfssl::CHACHA20_POLY1305_AEAD_KEYSIZE`
        // - `inIv` should be a valid pointer with size `wolfssl::CHACHA20_POLY1305_AEAD_IV_SIZE`
        // - `inAuthTag` should be a valid pointer with size `wolfssl::CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE`
        // - `inAAD` should be a valid pointer with size equal to `inAADLen`
        // - `inCiphertext` should be a valid pointer with size equal to `inCiphertextLen`
        // - `outPlainText` should be a valid mutable pointer with size equal to `inCiphertextLen`
        //
        // First three invariants are maintained using byteslice of respective sizes.
        // We do not use `inAAD`, hence it is null and 0.
        // `inCiphertext` is again a byteslice and `inCiphertextLen` is using len() of bytesslice
        // `outPlainText` we are creating a new BytesMut with same capacity as `inCiphertext` explicitly
        // [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__ChaCha20Poly1305.html#function-wc_chacha20poly1305_decrypt
        match unsafe {
            wc_ChaCha20Poly1305_Decrypt(
                self.key.as_ptr(),
                iv.as_ptr(),
                std::ptr::null(),
                0,
                cipher_text.as_ptr(),
                cipher_text.len() as u32,
                auth_tag.as_ptr(),
                plain_text.spare_capacity_mut().as_mut_ptr() as *mut u8,
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
    use super::Chacha20Poly1305Aead as Chacha20;

    const KEY: [u8; Chacha20::KEY_SIZE] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    const PLAIN_TEXT: [u8; 114] = [
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74,
        0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
        0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20,
        0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
        0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70,
        0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
        0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75,
        0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
    ];
    const IV: [u8; Chacha20::IV_SIZE] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];

    const CIPHER_TEXT: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
        0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
        0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
        0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
        0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
        0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
        0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    ];
    const AUTH_TAG: [u8; Chacha20::AUTHTAG_SIZE] = [
        0x6a, 0x23, 0xa4, 0x68, 0x1f, 0xd5, 0x94, 0x56, 0xae, 0xa1, 0xd2, 0x9f, 0x82, 0x47, 0x72,
        0x16,
    ];

    #[test]
    fn test_chacha20_encrypt() -> Result<(), String> {
        let cipher = Chacha20::new(KEY);

        let (cipher_text, auth_tag) = cipher.encrypt(IV, &PLAIN_TEXT).unwrap();
        assert_eq!(&cipher_text[..], &CIPHER_TEXT);
        assert_eq!(auth_tag, AUTH_TAG);
        Ok(())
    }

    #[test]
    fn test_chacha20_decrypt() -> Result<(), String> {
        let cipher = Chacha20::new(KEY);
        let plaint_text = cipher.decrypt(IV, &CIPHER_TEXT, AUTH_TAG).unwrap();
        assert_eq!(&plaint_text[..], &PLAIN_TEXT);
        Ok(())
    }
}
