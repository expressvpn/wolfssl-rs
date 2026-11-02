//! Criterion benchmarks for the wolfCrypt wrappers.
//!
//! `cargo bench -p wolfssl --bench crypto [-- <filter>]`

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use wolfssl::{Aes256Gcm, Chacha20Poly1305Aead, Random};

/// Small packet, typical VPN MTU, and a full TLS record
const SIZES: [usize; 3] = [64, 1350, 16384];

/// AEAD packet protocols typically authenticate a short header with each packet
const AAD: [u8; 18] = [0x5a; 18];

fn aes256_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes256_gcm");
    let mut cipher = Aes256Gcm::new().unwrap();
    cipher.set_key([0x42; Aes256Gcm::KEY_SIZE]).unwrap();
    let iv = [0x24; Aes256Gcm::IV_SIZE];

    for size in SIZES {
        let plain_text = vec![0xa5; size];
        let mut cipher_text = vec![0; size];
        let mut out = vec![0; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(BenchmarkId::new("encrypt", size), |b| {
            b.iter(|| {
                cipher
                    .encrypt_into(iv, black_box(&plain_text), &AAD, &mut cipher_text)
                    .unwrap()
            })
        });

        let auth_tag = cipher
            .encrypt_into(iv, &plain_text, &AAD, &mut cipher_text)
            .unwrap();
        group.bench_function(BenchmarkId::new("decrypt", size), |b| {
            b.iter(|| {
                cipher
                    .decrypt_into(iv, black_box(&cipher_text), &AAD, &auth_tag, &mut out)
                    .unwrap()
            })
        });
    }
    group.finish();
}

fn chacha20_poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20_poly1305");
    let cipher = Chacha20Poly1305Aead::new([0x42; Chacha20Poly1305Aead::KEY_SIZE]);
    let iv = [0x24; Chacha20Poly1305Aead::IV_SIZE];

    for size in SIZES {
        let plain_text = vec![0xa5; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(BenchmarkId::new("encrypt", size), |b| {
            b.iter(|| cipher.encrypt(iv, black_box(&plain_text)).unwrap())
        });

        let (cipher_text, auth_tag) = cipher.encrypt(iv, &plain_text).unwrap();
        group.bench_function(BenchmarkId::new("decrypt", size), |b| {
            b.iter(|| {
                cipher
                    .decrypt(iv, black_box(&cipher_text), auth_tag)
                    .unwrap()
            })
        });
    }
    group.finish();
}

fn random(c: &mut Criterion) {
    let mut rng = Random::new().unwrap();
    c.bench_function("random/u64", |b| b.iter(|| rng.random_u64().unwrap()));
    c.bench_function("random/bytes_32", |b| {
        b.iter(|| rng.random_bytes::<32>().unwrap())
    });
}

criterion_group!(benches, aes256_gcm, chacha20_poly1305, random);
criterion_main!(benches);
