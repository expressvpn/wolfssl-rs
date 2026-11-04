#ifndef _WIN_USER_SETTINGS_H_
#define _WIN_USER_SETTINGS_H_

#undef WOLFSSL_AESNI
#define WOLFSSL_AESNI

#undef HAVE_INTEL_RDSEED
#define HAVE_INTEL_RDSEED

/* Intel x86_64 assembly speedups (AES-GCM/ChaCha/Poly1305/SHA-2/SHA-3/
 * Curve25519/ML-KEM). The .asm files are assembled by passing
 * -p:WolfSSLIntelAsm=true to msbuild (see build.rs). */
#undef USE_INTEL_SPEEDUP
#define USE_INTEL_SPEEDUP

/* Keep the AVX-512 kernels out of the C dispatch for now; they have not been
 * exercised on Windows yet. build.rs mirrors this to ml64 (WolfSSLIntelAsmDefs)
 * so the assembly matches. AVX1/AVX2 and VAES stay enabled: on Arrow Lake and
 * Lunar Lake, where VAES AES-GCM is ~20% slower than AVX2, wolfSSL's CPUID
 * tuning (CPUID_SLOW_VAES, wolfSSL PR #11986) skips VAES at run time. */
#undef NO_AVX512_SUPPORT
#define NO_AVX512_SUPPORT

/* Single precision x86_64 assembly for RSA/ECC (sp_x86_64_asm.asm). The vcxproj
 * is assembled for x64 with the SP sizes build.rs passes in WolfSSLSpAsmDefs,
 * which must match the WOLFSSL_SP_* sizes in user_settings-common.h. This
 * does not need USE_INTEL_SPEEDUP; BMI2/ADX variants are picked on CPUID. */
#undef WOLFSSL_SP_ASM
#define WOLFSSL_SP_ASM

#undef WOLFSSL_SP_X86_64_ASM
#define WOLFSSL_SP_X86_64_ASM

#undef WOLFSSL_X86_64_BUILD
#define WOLFSSL_X86_64_BUILD

#endif /* _WIN_USER_SETTINGS_H_ */
