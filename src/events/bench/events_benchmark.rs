#![feature(test)]

#[macro_use]
extern crate criterion;

extern crate causality;
extern crate crypto;
extern crate events;
extern crate network;
extern crate patricia_trie;
extern crate persistence;
extern crate test;
extern crate test_helpers;
extern crate transactions;

use causality::Stamp;
use criterion::Criterion;
use crypto::{Hash, Identity};
use events::Heartbeat;
use network::NodeId;
use patricia_trie::{TrieDBMut, TrieMut};
use persistence::{BlakeDbHasher, Codec};
use test::Bencher;
use transactions::Tx;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("calculate root hash 30", |b| {
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let id = Identity::new();
        let mut txs: Vec<Box<Tx>> = Vec::with_capacity(30);

        for _ in 0..30 {
            txs.push(Box::new(Tx::arbitrary_valid(&mut trie)));
        }

        let mut hb = Heartbeat {
            node_id: NodeId::from_pkey(*id.pkey()),
            stamp: Stamp::seed(),
            parent_hash: Hash::random(),
            transactions: txs,
            root_hash: None,
            signature: None,
            hash: None,
        };

        b.iter(|| hb.calculate_root_hash())
    });

    c.bench_function("deserialize 30", |b| {
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let id = Identity::new();
        let mut txs: Vec<Box<Tx>> = Vec::with_capacity(30);

        for _ in 0..30 {
            txs.push(Box::new(Tx::arbitrary_valid(&mut trie)));
        }

        let mut hb = Heartbeat {
            node_id: NodeId::from_pkey(*id.pkey()),
            parent_hash: Hash::random(),
            stamp: Stamp::seed(),
            transactions: txs,
            root_hash: None,
            signature: None,
            hash: None,
        };

        hb.calculate_root_hash();
        hb.sign(id.skey().clone());
        hb.hash();

        let serialized = hb.to_bytes().unwrap();

        b.iter(|| Heartbeat::from_bytes(&serialized))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
