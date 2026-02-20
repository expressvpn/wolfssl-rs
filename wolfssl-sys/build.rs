/*!build
 * Contains the build process for WolfSSL
 */

extern crate bindgen;

use autotools::Config;
#[cfg(windows)]
use msbuild::MsBuild;
use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/**
 * Work around for bindgen creating duplicate values.
 */
#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

/**
 * Copy WolfSSL
 */
fn copy_wolfssl(dest: &Path) -> std::io::Result<PathBuf> {
    println!("cargo:rerun-if-changed=wolfssl-src");

    let src = Path::new("wolfssl-src");
    let dest_dir = dest.join("wolfssl-src");

    copy_dir_recursive(src, &dest_dir)?;

    if build_target::target_os() == build_target::Os::Windows {
        // Determine architecture-specific user_settings file
        let arch_settings = match build_target::target_arch() {
            build_target::Arch::X86_64 => "windows/user_settings-x86_64.h",
            build_target::Arch::X86 => "windows/user_settings-x86.h",
            build_target::Arch::AArch64 => "windows/user_settings-arm64.h",
            _ => panic!("Unsupported architecture for Windows"),
        };

        // Create combined user_settings.h by concatenating common + arch-specific
        let common_content = fs::read_to_string("windows/user_settings-common.h")
            .expect("Failed to read user_settings-common.h");
        let arch_content = fs::read_to_string(arch_settings)
            .unwrap_or_else(|_| panic!("Failed to read {}", arch_settings));

        let mut combined_content = format!("{}\n{}", common_content, arch_content);

        // Enable CFLAGS based on features
        if cfg!(feature = "debug") {
            combined_content.push_str("#define HAVE_SECRET_CALLBACK\n");
            combined_content.push_str("#define DEBUG_WOLFSSL\n");
        };

        if cfg!(feature = "system_ca_certs") {
            combined_content.push_str("#define ENABLED_SYS_CA_CERTS yes\n");
        };

        // Write the combined content to user_settings.h file

        let settings_path = dest_dir.join("wolfssl").join("user_settings.h");
        fs::write(&settings_path, &combined_content).unwrap();
        println!("Created user settings at {}", settings_path.display());

        let settings_path = dest_dir.join("IDE").join("WIN").join("user_settings.h");
        fs::write(&settings_path, &combined_content).unwrap();
        println!("Created user settings at {}", settings_path.display());

        let command = Command::new("git")
            .args(["init", "."])
            .current_dir(&dest_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to execute git init");

        let output = command
            .wait_with_output()
            .expect("Failed to wait for git init");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);

            panic!(
                "Failed to git init: {}\nStdout: {}\nStderr: {}",
                output.status, stdout, stderr
            );
        }
    }

    Ok(dest_dir)
}

/**
 * Recursively copy a directory and its contents
 */
fn copy_dir_recursive(src: &Path, dest: &Path) -> std::io::Result<()> {
    if !dest.exists() {
        fs::create_dir_all(dest).inspect_err(|e| {
            println!("Error while creating dir: {:?}", e);
        })?;
    }

    let dir_contents = fs::read_dir(src).inspect_err(|e| {
        println!("Error while reading dir {:?}: {:?}", src, e);
    })?;

    for entry in dir_contents {
        let entry = entry?;
        let src_path = entry.path();
        let dest_path = dest.join(entry.file_name());

        if entry.file_name() == ".git" {
            // Skip copying .git
        } else if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dest_path)?
        } else {
            fs::copy(&src_path, &dest_path).inspect_err(|e| {
                println!(
                    "Error while copying dir {:?}->{:?}: {:?}",
                    src_path, dest_path, e
                );
            })?;
        }
    }

    Ok(())
}

const PATCH_DIR: &str = "patches";
const PATCHES: &[&str] = &[
    "CVPN-1945-Lower-max-mtu-for-DTLS-1.3-handshake-message.patch",
    "backport-darwin-address-calc-fix.patch",
    "ChaCha20-Aarch64-ASM-fix-256-bit-case-fixed.patch",
    "dtls13-rtx-timer.patch",
];
const OPTIONAL_FEATURES: &[&str] = &["aesccm", "dh", "opensslall", "opensslextra", "psk"];
const MACRO_FEATURES: &[(&str, &str)] = &[("ex_data", "HAVE_EX_DATA"), ("alpn", "HAVE_ALPN")];

/**
 * Apply patch using git apply (Windows)
 */
#[cfg(windows)]
fn apply_patch(wolfssl_path: &Path, patch: impl AsRef<Path>) -> Result<(), String> {
    let full_patch = Path::new(PATCH_DIR).join(patch.as_ref());
    // Get absolute path to patch file since we'll change working directory
    let abs_patch = std::env::current_dir().unwrap().join(&full_patch);

    println!("cargo:rerun-if-changed={}", full_patch.display());

    let patch_file = File::open(&abs_patch)
        .map_err(|e| format!("Failed to open patch file {}: {}", abs_patch.display(), e))?;

    let command = Command::new("git")
        .args(["apply", "--verbose"])
        .current_dir(wolfssl_path)
        .stdin(Stdio::from(patch_file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to execute git apply: {}", e))?;

    let output = command
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for git apply: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        return Err(format!(
            "Failed to apply patch {}: {}\nStdout: {}\nStderr: {}",
            patch.as_ref().display(),
            output.status,
            stdout,
            stderr
        ));
    }

    println!("Successfully applied patch: {}", patch.as_ref().display());
    Ok(())
}

/**
 * Apply patch using `patch` (Unix)
 */
#[cfg(unix)]
fn apply_patch(wolfssl_path: &Path, patch: impl AsRef<Path>) -> Result<(), String> {
    let full_patch = Path::new(PATCH_DIR).join(patch.as_ref());

    println!("cargo:rerun-if-changed={}", full_patch.display());

    let patch_buffer = File::open(full_patch).unwrap();
    let status = Command::new("patch")
        .arg("-d")
        .arg(wolfssl_path)
        .arg("-p1")
        .stdin(patch_buffer)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "Failed to apply {}",
        patch.as_ref().display()
    );
    Ok(())
}

/**
 * Get Windows build configuration and platform based on build profile and target architecture
 */
fn get_windows_build_params() -> (&'static str, &'static str) {
    let configuration = if cfg!(debug_assertions) {
        "Debug"
    } else {
        "Release"
    };

    let platform = match build_target::target_arch() {
        build_target::Arch::X86_64 => "x64",
        build_target::Arch::X86 => "Win32",
        build_target::Arch::AArch64 => "ARM64",
        _ => panic!("Unsupported architecture for Windows"),
    };

    (configuration, platform)
}

/**
Builds WolfSSL in windows
*/
#[cfg(windows)]
fn build_win(wolfssl_src: &Path) -> PathBuf {
    let msb = MsBuild::find_msbuild(Some("2022")).expect("Failed to find MsBuild 2022");

    let (configuration, platform) = get_windows_build_params();

    msb.run(
        wolfssl_src,
        &[
            ".\\wolfssl.vcxproj",
            "-t:Build",
            &format!("-p:Configuration={}", configuration),
            &format!("-p:Platform={}", platform),
            "-p:PlatformToolset=v143",
        ],
    )
    .expect("Failed to build WolfSSL");
    wolfssl_src.to_path_buf()
}

/**
Builds WolfSSL
*/
fn build_wolfssl(wolfssl_src: &Path) -> PathBuf {
    #[cfg(windows)]
    if build_target::target_os() == build_target::Os::Windows {
        return build_win(wolfssl_src);
    }
    // Create the config
    let mut conf = Config::new(wolfssl_src);
    // Configure it
    conf.reconf("-ivf")
        // Disable benchmarks
        .disable("benchmark", None)
        // Disable examples
        .disable("examples", None)
        // Disable old TLS versions
        .disable("oldtls", None)
        // Disable SHA3
        .disable("sha3", None)
        // Disable dynamic library
        .disable_shared()
        // Disable sys ca certificate store
        .disable("sys-ca-certs", None)
        // Disable dilithium
        .disable("dilithium", None)
        // Enable AES bitsliced implementation (cache attack safe)
        .enable("aes-bitsliced", None)
        // Enable Curve25519
        .enable("curve25519", None)
        // Enable D/TLS
        .enable("dtls", None)
        // Enable DTLS/1.3
        .enable("dtls13", None)
        // Enable DTLS1.3 ClientHello fragmentation
        .enable("dtls-frag-ch", None)
        // Enable setting the D/TLS MTU size
        .enable("dtls-mtu", None)
        // Enable Secure Renegotiation
        .enable("secure-renegotiation", None)
        // Enable single threaded mode
        .enable("singlethreaded", None)
        // Enable SNI
        .enable("sni", None)
        // Enable single precision 4096 bits RSA/DH support
        // https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#-enable-spopt
        .enable("sp", Some("yes,4096"))
        // Enable single precision ASM
        .enable("sp-asm", None)
        // Only build the static library
        .enable_static()
        // Enable elliptic curve exchanges
        .enable("supportedcurves", None)
        // Enable TLS/1.3
        .enable("tls13", None)
        // Enable kyber, etc
        .enable("experimental", None)
        // CFLAGS
        .cflag("-g")
        .cflag("-fPIC")
        .cflag("-DWOLFSSL_DTLS_ALLOW_FUTURE")
        .cflag("-DDTLS13_MIN_RTX_INTERVAL=100")
        .cflag("-DWOLFSSL_MIN_RSA_BITS=2048")
        .cflag("-DWOLFSSL_MIN_ECC_BITS=256")
        .cflag("-DUSE_CERT_BUFFERS_4096")
        .cflag("-DUSE_CERT_BUFFERS_256")
        .cflag("-DWOLFSSL_NO_SPHINCS")
        .cflag("-DWOLFSSL_TLS13_MIDDLEBOX_COMPAT");

    for feature in OPTIONAL_FEATURES {
        // Determine if feature is enabled, enable or disable feature in configure
        // script based on that.
        // For each optional feature, cargo sets the CARGO_FEATURE_<name> env var,
        // so we check for that.
        // Using cfg!() only works in a compile-time context, so this is the best
        // alternative that does not require defining extra macros.
        if env::var(format!(
            "CARGO_FEATURE_{}",
            feature.to_uppercase().replace("-", "_")
        ))
        .is_ok()
        {
            conf.enable(feature, None);
        } else {
            conf.disable(feature, None);
        }
    }
    for (feature_name, feature_define) in MACRO_FEATURES {
        // Same as above, just for features that are enabled/disabled via defines.
        // Alongside the feature name, MACRO_FEATURES contains the define name to set.
        if env::var(format!(
            "CARGO_FEATURE_{}",
            feature_name.to_uppercase().replace("-", "_")
        ))
        .is_ok()
        {
            conf.cflag(format!("-D{}", feature_define));
        }
    }

    if cfg!(feature = "debug") {
        conf.enable("debug", None);
        conf.cflag("-DHAVE_SECRET_CALLBACK");
    }

    if cfg!(feature = "postquantum") {
        let flags = if cfg!(feature = "kyber_only") {
            "yes,kyber"
        } else {
            conf.cflag("-DWOLFSSL_ML_KEM_USE_OLD_IDS");
            "yes,all"
        };
        // Enable Kyber/ML-KEM
        conf.enable("mlkem", Some(flags))
            // SHA3 is needed for using WolfSSL's implementation of Kyber/ML-KEM
            .enable("sha3", None);
    }

    if cfg!(feature = "system_ca_certs") {
        conf.enable("sys-ca-certs", None);
    }

    match build_target::target_arch() {
        build_target::Arch::AArch64 => {
            // Enable ARM ASM optimisations
            conf.enable("armasm", None);
        }
        build_target::Arch::Arm => {
            // Enable ARM ASM optimisations, except for android armeabi-v7a
            if build_target::target_os() != build_target::Os::Android {
                conf.enable("armasm", None);
            }
        }
        build_target::Arch::X86 => {
            // Disable sp asm optmisations which has been enabled earlier
            conf.disable("sp-asm", None);
        }
        build_target::Arch::X86_64 => {
            // We don't need these build flag for iOS simulator
            if !(build_target::target_os() == build_target::Os::iOS
                && build_target::target_env()
                    == build_target::Env::Other(String::from("sim")).into())
            {
                // Enable Intel ASM optmisations
                conf.enable("intelasm", None);
                // Enable AES hardware acceleration
                conf.enable("aesni", None);
            }
        }
        build_target::Arch::Riscv64 => {
            // Enable the RISCV acceleration
            conf.enable("riscv-asm", None);
            // Disable sp asm optmisations on RISC-V
            conf.disable("sp-asm", None);
            // Stop frame pointer s0 in RISC-V from being contested
            conf.cflag("-fomit-frame-pointer");
        }
        _ => {}
    }

    if build_target::target_os() == build_target::Os::Android {
        // Build options for Android
        let (chost, arch_flags, arch, configure_platform) = match build_target::target_arch() {
            build_target::Arch::Arm => (
                "armv7a-linux-androideabi",
                "-march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3-d16 -O3",
                "armeabi-v7a",
                "android-arm",
            ),
            build_target::Arch::AArch64 => (
                "aarch64-linux-android",
                "-march=armv8-a+crypto -O3",
                "arm64-v8a",
                "android-arm64",
            ),
            build_target::Arch::X86 => (
                "i686-linux-android",
                "-march=i686 -msse3 -m32 -O3",
                "x86",
                "android-x86",
            ),
            build_target::Arch::X86_64 => (
                "x86_64-linux-android",
                "-march=x86-64 -msse4.2 -mpopcnt -m64 -O3",
                "x86_64",
                "android64-x86_64",
            ),
            _ => panic!("Unsupported build_target for Android"),
        };

        // Per arch configurations
        conf.config_option("host", Some(chost));
        conf.cflag(arch_flags);
        conf.env("ARCH", arch);
        conf.env("CONFIGURE_PLATFORM", configure_platform);

        // General Android specific configurations
        conf.disable("crypttests", None);
        conf.cflag("-DFP_MAX_BITS=8192");
        conf.cflag("-fomit-frame-pointer");
        conf.env("LIBS", "-llog -landroid");
    }

    if build_target::target_os() == build_target::Os::MacOS {
        // Check whether we have set MACOSX_DEPLOYMENT_TARGET to ensure we support older MacOS
        let deployment_target = env::var("MACOSX_DEPLOYMENT_TARGET")
            .expect("Must have set minimum supported MacOS version (MACOSX_DEPLOYMENT_TARGET)");
        if deployment_target.is_empty() {
            panic!("MACOSX_DEPLOYMENT_TARGET is empty")
        }

        // Build options for MacOS
        let chost = match build_target::target_arch() {
            build_target::Arch::AArch64 => "arm64-apple-darwin",
            build_target::Arch::X86_64 => "x86_64-apple-darwin",
            _ => panic!("Unsupported build_target for MacOS"),
        };

        // Per arch configurations
        conf.config_option("host", Some(chost));
    }

    if build_target::target_os() == build_target::Os::iOS {
        // Check whether we have set IPHONEOS_DEPLOYMENT_TARGET to ensure we support older iOS
        let ios_target = env::var("IPHONEOS_DEPLOYMENT_TARGET")
            .expect("Must have set minimum supported iOS version (IPHONEOS_DEPLOYMENT_TARGET)");
        if ios_target.is_empty() {
            panic!("IPHONEOS_DEPLOYMENT_TARGET is empty")
        }

        // Check if we are building for Mac Catalyst or iOS device
        let arm64_arch = if build_target::target_env()
            == build_target::Env::Other(String::from("macabi")).into()
        {
            "arm64-apple-darwin"
        } else {
            "arm64-apple-ios"
        };

        // Build options for iOS/Mac Catalyst
        let (chost, arch_flags, arch) = match build_target::target_arch() {
            build_target::Arch::AArch64 => (arm64_arch, "-O3", "arm64"),
            build_target::Arch::X86_64 => ("x86_64-apple-darwin", "-O3", "x86_64"),
            _ => panic!("Unsupported build_target for iOS"),
        };

        // Per arch configurations
        conf.config_option("host", Some(chost));
        conf.cflag(arch_flags);
        conf.cxxflag(arch_flags);
        conf.env("ARCH", arch);

        // General iOS specific configurations
        conf.disable("crypttests", None);
        conf.cflag("-D_FORTIFY_SOURCE=2");
        if cfg!(feature = "system_ca_certs") {
            conf.cflag("-DWOLFSSL_APPLE_NATIVE_CERT_VALIDATION");
        }
    }

    if build_target::target_os() == build_target::Os::TvOS {
        // Check whether we have set TVOS_DEPLOYMENT_TARGET to ensure we support older tvOS
        let ios_target = env::var("TVOS_DEPLOYMENT_TARGET")
            .expect("Must have set minimum supported tvOS version");
        if ios_target.is_empty() {
            panic!("TVOS_DEPLOYMENT_TARGET is empty")
        }

        // Build options for tvos
        let (chost, arch_flags, arch) = match build_target::target_arch() {
            build_target::Arch::AArch64 => ("arm64-apple-ios", "-O3", "arm64"),
            build_target::Arch::X86_64 => ("x86_64-apple-darwin", "-O3", "x86_64"), // for tvOS simulator
            _ => panic!("Unsupported build_target for tvos"),
        };

        // Per arch configurations
        conf.config_option("host", Some(chost));
        conf.cflag(arch_flags);
        conf.cxxflag(arch_flags);
        conf.env("ARCH", arch);

        // General tvOS specific configurations
        conf.disable("crypttests", None);
        conf.cflag("-D_FORTIFY_SOURCE=2");
        if cfg!(feature = "system_ca_certs") {
            conf.cflag("-DWOLFSSL_APPLE_NATIVE_CERT_VALIDATION");
        }
    }

    // Build and return the config
    conf.build()
}

fn main() -> std::io::Result<()> {
    // Get the build directory
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Extract WolfSSL
    let wolfssl_src = copy_wolfssl(&out_dir)?;

    // Apply patches
    for &patch_file in PATCHES.iter() {
        apply_patch(&wolfssl_src, patch_file)
            .unwrap_or_else(|e| panic!("Failed to apply patch {}: {}", patch_file, e));
    }
    println!("cargo:rerun-if-changed={PATCH_DIR}");

    // Configure and build WolfSSL
    let wolfssl_install_dir = build_wolfssl(&wolfssl_src);

    // We want to block some macros as they are incorrectly creating duplicate values
    // https://github.com/rust-lang/rust-bindgen/issues/687
    // TODO: Reach out to tlspuffin and ask if we can incorporate this code and credit them
    let mut hash_ignored_macros = HashSet::new();
    for i in &[
        "IPPORT_RESERVED",
        "EVP_PKEY_DH",
        "BIO_CLOSE",
        "BIO_NOCLOSE",
        "CRYPTO_LOCK",
        "ASN1_STRFLGS_ESC_MSB",
        "SSL_MODE_RELEASE_BUFFERS",
        // Wolfssl 4.3.0
        "GEN_IPADD",
        "EVP_PKEY_RSA",
    ] {
        hash_ignored_macros.insert(i.to_string());
    }

    let ignored_macros = IgnoreMacros(hash_ignored_macros);
    let wolfssl_include_dir = wolfssl_install_dir.join("include");

    // Set cargo metadata to allow dependent libraries to reference the built library.
    // https://doc.rust-lang.org/cargo/reference/build-script-examples.html#using-another-sys-crate
    println!("cargo:root={}", wolfssl_install_dir.to_str().unwrap());
    println!("cargo:include={}", wolfssl_include_dir.to_str().unwrap());

    // Build the Rust binding
    let builder = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}/", wolfssl_include_dir.to_str().unwrap()))
        .parse_callbacks(Box::new(ignored_macros))
        .formatter(bindgen::Formatter::Rustfmt);

    let builder = if build_target::target_os() == build_target::Os::Windows {
        let user_settings_path = wolfssl_install_dir.join("wolfssl").join("user_settings.h");
        builder
            .clang_arg(format!("-include{}", user_settings_path.to_str().unwrap()))
            .clang_arg(format!("-I{}/", wolfssl_install_dir.to_str().unwrap()))
    } else {
        [
            "wolfssl/.*.h",
            "wolfssl/wolfcrypt/.*.h",
            "wolfssl/openssl/compat_types.h",
        ]
        .iter()
        .fold(builder, |b, p| {
            b.allowlist_file(wolfssl_include_dir.join(p).to_str().unwrap())
        })
    };

    let builder = builder.blocklist_function("wolfSSL_BIO_vprintf");

    let bindings: bindgen::Bindings = builder.generate().expect("Unable to generate bindings");

    // Write out the bindings
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Tell cargo to tell rustc to link in WolfSSL
    if build_target::target_os() == build_target::Os::Windows {
        let (configuration, platform) = get_windows_build_params();

        println!(
            "cargo:rustc-link-search=native={}",
            wolfssl_install_dir
                .join(configuration)
                .join(platform)
                .to_str()
                .unwrap()
        );
        // On Windows, we link the static library with whole-archive to avoid issues with
        // missing symbols when using the wolfSSL library.
        // Ref: https://doc.rust-lang.org/rustc/command-line-arguments.html#linking-modifiers-whole-archive
        println!("cargo:rustc-link-lib=static:+whole-archive=wolfssl");

        // Windows system libraries needed by wolfSSL random object
        println!("cargo:rustc-link-lib=dylib=Advapi32");
    } else {
        println!(
            "cargo:rustc-link-search=native={}",
            wolfssl_install_dir.join("lib").to_str().unwrap()
        );
        println!("cargo:rustc-link-lib=static=wolfssl");
        if cfg!(feature = "system_ca_certs")
            && (build_target::target_os() == build_target::Os::iOS
                || build_target::target_os() == build_target::Os::MacOS
                || build_target::target_os() == build_target::Os::TvOS)
        {
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-link-lib=framework=Security");
        }
    }

    // Invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // That should do it...
    Ok(())
}
