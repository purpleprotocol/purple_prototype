//#![feature(test)]

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use network::packets::*;
use network::Packet;
use quickcheck::{Arbitrary, StdGen};
use std::sync::Arc;
use transactions::Tx;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("deserialize SendSubPiece packet 16kb data", |b| {
        let rng = rand::thread_rng();
        let mut gen = StdGen::new(rng, 100);

        let sub_piece: Vec<u8> = (0..SUB_PIECE_MAX_SIZE)
            .into_iter()
            .map(|_| Arbitrary::arbitrary(&mut gen))
            .collect();

        let packet = SendSubPiece::new(sub_piece, 14324324325);
        let packet_bytes = packet.to_bytes();

        b.iter(|| SendSubPiece::from_bytes(&packet_bytes));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
