#ifndef _WIN_USER_SETTINGS_H_
#define _WIN_USER_SETTINGS_H_

#undef WOLFSSL_AESNI
#define WOLFSSL_AESNI

#undef HAVE_INTEL_RDSEED
#define HAVE_INTEL_RDSEED

#undef USE_INTEL_SPEEDUP
// #define USE_INTEL_SPEEDUP // Needs ASM stubs which are not included in the vxproj

// AVX1/AVX2 AES-GCM paths in aes_gcm_asm.asm; selected at runtime via cpuid
#undef HAVE_INTEL_AVX1
#define HAVE_INTEL_AVX1

#undef HAVE_INTEL_AVX2
#define HAVE_INTEL_AVX2

// AVX/AVX2 ChaCha20 (chacha_asm.asm) and Poly1305 (poly1305_asm.asm)
#undef USE_INTEL_CHACHA_SPEEDUP
#define USE_INTEL_CHACHA_SPEEDUP

#undef USE_INTEL_POLY1305_SPEEDUP
#define USE_INTEL_POLY1305_SPEEDUP

// Assembly single-precision math for RSA/ECC (sp_x86_64_asm.asm)
#undef WOLFSSL_SP_ASM
#define WOLFSSL_SP_ASM

#undef WOLFSSL_SP_X86_64_ASM
#define WOLFSSL_SP_X86_64_ASM

#undef WOLFSSL_X86_64_BUILD
#define WOLFSSL_X86_64_BUILD

#endif /* _WIN_USER_SETTINGS_H_ */
