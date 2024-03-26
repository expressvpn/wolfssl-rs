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
