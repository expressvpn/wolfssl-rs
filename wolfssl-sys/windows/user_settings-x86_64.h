#ifndef _WIN_USER_SETTINGS_H_
#define _WIN_USER_SETTINGS_H_

#undef WOLFSSL_AESNI
#define WOLFSSL_AESNI

#undef HAVE_INTEL_RDSEED
#define HAVE_INTEL_RDSEED

#undef USE_INTEL_SPEEDUP
// #define USE_INTEL_SPEEDUP // Needs ASM stubs which are not included in the vxproj

/* Single precision x86_64 assembly for RSA/ECC (sp_x86_64_asm.asm). The vcxproj
 * always assembles it for x64 with /DWOLFSSL_SP_384 /DWOLFSSL_SP_4096, matching
 * the WOLFSSL_SP_384 / WOLFSSL_SP_4096 enabled in user_settings-common.h. This
 * does not need USE_INTEL_SPEEDUP; BMI2/ADX variants are picked on CPUID. */
#undef WOLFSSL_SP_ASM
#define WOLFSSL_SP_ASM

#undef WOLFSSL_SP_X86_64_ASM
#define WOLFSSL_SP_X86_64_ASM

#undef WOLFSSL_X86_64_BUILD
#define WOLFSSL_X86_64_BUILD

#endif /* _WIN_USER_SETTINGS_H_ */
