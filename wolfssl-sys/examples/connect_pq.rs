/// This is an example application that attempts to connect to the OQS test site
/// using the hybrid P521 and Kyber Level 5 key exchange. The test site port that
/// we use only offers this specific combination, making it an effective test.
///
/// Note: This tool is built with unsafe primitives with limited error handling or
///       checking. This is to demonstrate how easy it is to use WolfSSL to gain PQ
///       protection, even if you roll it entirely by hand. Generally you would use
///       a higher level API (which hasn't been written yet) to gain access to these
///       features. In the meantime, you can see it here, but do not base any real
///       world system on this raw code!
///
use wolfssl_sys as ffi;

use std::net::TcpStream;
use std::os::unix::io::AsRawFd;

use std::ffi::CStr;
use std::ffi::CString;

fn main() {
    // The website we're going to test against
    let site = "test.openquantumsafe.org";
    let site_len = site.len() as u16;
    // There admittedly has to be something better than this...
    let sitec = CString::new(site)
        .expect("Couldn't convert URL to a c string")
        .as_c_str()
        .as_ptr() as *mut ::std::os::raw::c_void;
    // The port that runs P521 Kyber Level 5 hybrid
    let port = 6043;

    // Compile in the OQS CA at build time
    let pq_osa_ca = include_bytes!("test_certs/pq-osa-ca.crt");
    // Cast to what the ffi functions are looking for
    let pq_osa_ca_size = pq_osa_ca.len() as i64;
    let pq_osa_ca = pq_osa_ca as *const u8;

    // We'll do everything else in an unsafe block as it's clearer than wrapping each function
    // in its own block.
    unsafe {
        // Init WolfSSL
        ffi::wolfSSL_Init();

        // Set up client method
        let method = ffi::wolfTLSv1_3_client_method();

        // Create context
        let context = ffi::wolfSSL_CTX_new(method);

        // Load in the CA
        ffi::wolfSSL_CTX_load_verify_buffer(
            context,
            pq_osa_ca,
            pq_osa_ca_size,
            ffi::WOLFSSL_FILETYPE_PEM,
        );

        // Enable SNI
        ffi::wolfSSL_CTX_UseSNI(context, ffi::WOLFSSL_SNI_HOST_NAME as u8, sitec, site_len);

        // Create new SSL stream
        let ssl = ffi::wolfSSL_new(context);

        // Enable Kyber
        let res = ffi::wolfSSL_UseKeyShare(ssl, ffi::WOLFSSL_P521_KYBER_LEVEL5 as u16);

        // Check that Kyber was enabled
        assert_eq!(res, ffi::WOLFSSL_SUCCESS);

        // Try to open a TCP stream to OQS test site - 6007
        let stream = TcpStream::connect(format!("{}:{}", site, port))
            .expect("Couldn't connect to test site");

        // Tell WolfSSL what the file descriptor is for the stream
        ffi::wolfSSL_set_fd(ssl, stream.as_raw_fd());

        // Try to connect
        let res = ffi::wolfSSL_connect(ssl);

        // Exit out here if we didn't complete the handshake
        if res != ffi::WOLFSSL_SUCCESS {
            println!(
                "Connection failed with error: {}",
                ffi::wolfSSL_get_error(ssl, res)
            );
            std::process::exit(-1);
        }

        println!("Connected to {}", site);
        println!(
            "Key Exchange: {:?}",
            CStr::from_ptr(ffi::wolfSSL_get_curve_name(ssl))
        );
        println!(
            "Cipher: {:?}",
            CStr::from_ptr(ffi::wolfSSL_get_cipher_name(ssl))
        );
    }
}
