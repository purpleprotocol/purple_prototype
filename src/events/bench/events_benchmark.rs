#![feature(test)]

#[macro_use]
extern crate criterion;

extern crate test_helpers;
extern crate crypto;
extern crate patricia_trie;
extern crate persistence;
extern crate test;
extern crate events;
extern crate transactions;
extern crate causality;
extern crate network;

use events::Heartbeat;
use crypto::{Hash, Identity};
use test::Bencher;
use patricia_trie::{TrieMut, TrieDBMut};
use persistence::{BlakeDbHasher, Codec};
use criterion::Criterion;
use transactions::Tx;
use causality::Stamp;
use network::NodeId;

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
            transactions: txs,
            root_hash: None,
            signature: None,
            hash: None
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
            stamp: Stamp::seed(),
            transactions: txs,
            root_hash: None,
            signature: None,
            hash: None
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