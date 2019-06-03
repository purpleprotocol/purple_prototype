#![feature(test)]

#[macro_use]
extern crate criterion;
extern crate crypto;

use criterion::Criterion;
use crypto::*;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("bls_single_sign", |b| {
        let (pk, sk) = gen_bls_keypair();
        let message = b"test_message";
        b.iter(|| bls_sign(message, &sk));
    });

    c.bench_function("bls_single_verify", |b| {
        let (pk, sk) = gen_bls_keypair();
        let message = b"test_message";
        let sig = bls_sign(message, &sk);

        b.iter(|| bls_verify(message, &sig, &pk));
    });

    c.bench_function("ed25519_verify", |b| {
        let (pk, sk) = gen_keypair();
        let message = b"test_message";
        let sig = sign(message, &sk);

        b.iter(|| verify(message, &sig, &pk));
    });

    c.bench_function("ed25519_sign", |b| {
        let (pk, sk) = gen_keypair();
        let message = b"test_message";
        b.iter(|| sign(message, &sk));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);