//#![feature(test)]

#[macro_use]
extern crate criterion;

use network::packets::*;
use network::Packet;
use quickcheck::{StdGen, Arbitrary};
use criterion::Criterion;
use transactions::Tx;
use std::sync::Arc;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("deserialize SendMissingTxs packet 1000 txs", |b| {
        let rng = rand::thread_rng();
        let mut gen = StdGen::new(rng, 100);

        let txs: Vec<Arc<Tx>> = (0..1000)
            .into_iter()
            .map(|_| Arbitrary::arbitrary(&mut gen))
            .collect();

        let packet = SendMissingTxs::new(100, txs);
        let packet_bytes = packet.to_bytes();

        b.iter(|| SendMissingTxs::from_bytes(&packet_bytes));
    });

    c.bench_function("deserialize SendMissingTxs packet 2500 txs", |b| {
        let rng = rand::thread_rng();
        let mut gen = StdGen::new(rng, 100);

        let txs: Vec<Arc<Tx>> = (0..2500)
            .into_iter()
            .map(|_| Arbitrary::arbitrary(&mut gen))
            .collect();

        let packet = SendMissingTxs::new(100, txs);
        let packet_bytes = packet.to_bytes();

        b.iter(|| SendMissingTxs::from_bytes(&packet_bytes));
    });

    c.bench_function("deserialize SendMissingTxs packet 5000 txs", |b| {
        let rng = rand::thread_rng();
        let mut gen = StdGen::new(rng, 100);

        let txs: Vec<Arc<Tx>> = (0..5000)
            .into_iter()
            .map(|_| Arbitrary::arbitrary(&mut gen))
            .collect();

        let packet = SendMissingTxs::new(100, txs);
        let packet_bytes = packet.to_bytes();

        b.iter(|| SendMissingTxs::from_bytes(&packet_bytes));
    });

    c.bench_function("deserialize SendMissingTxs packet 8000 txs", |b| {
        let rng = rand::thread_rng();
        let mut gen = StdGen::new(rng, 100);

        let txs: Vec<Arc<Tx>> = (0..8000)
            .into_iter()
            .map(|_| Arbitrary::arbitrary(&mut gen))
            .collect();

        let packet = SendMissingTxs::new(100, txs);
        let packet_bytes = packet.to_bytes();

        b.iter(|| SendMissingTxs::from_bytes(&packet_bytes));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
