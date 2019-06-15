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
extern crate quickcheck;
extern crate rand;

use causality::Stamp;
use criterion::Criterion;
use crypto::{Hash, Identity};
use events::Heartbeat;
use network::NodeId;
use patricia_trie::{TrieDBMut, TrieMut};
use persistence::{BlakeDbHasher, Codec};
use test::Bencher;
use transactions::Tx;
use std::sync::Arc;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("calculate root hash 30", |b| {
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let id = Identity::new();
        let mut txs: Vec<Arc<Tx>> = Vec::with_capacity(30);
        let thread_rng = rand::thread_rng();
        let mut g = quickcheck::StdGen::new(thread_rng, 100);

        for _ in 0..30 {
            txs.push(Arc::new(quickcheck::Arbitrary::arbitrary(&mut g)));
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

    c.bench_function("calculate root hash 100", |b| {
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let id = Identity::new();
        let mut txs: Vec<Arc<Tx>> = Vec::with_capacity(100);
        let thread_rng = rand::thread_rng();
        let mut g = quickcheck::StdGen::new(thread_rng, 100);

        for _ in 0..100 {
            txs.push(Arc::new(quickcheck::Arbitrary::arbitrary(&mut g)));
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

    c.bench_function("calculate root hash 500", |b| {
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let id = Identity::new();
        let mut txs: Vec<Arc<Tx>> = Vec::with_capacity(500);
        let thread_rng = rand::thread_rng();
        let mut g = quickcheck::StdGen::new(thread_rng, 100);

        for _ in 0..500 {
            txs.push(Arc::new(quickcheck::Arbitrary::arbitrary(&mut g)));
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

    c.bench_function("calculate root hash 1000", |b| {
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let id = Identity::new();
        let mut txs: Vec<Arc<Tx>> = Vec::with_capacity(1000);
        let thread_rng = rand::thread_rng();
        let mut g = quickcheck::StdGen::new(thread_rng, 100);

        for _ in 0..1000 {
            txs.push(Arc::new(quickcheck::Arbitrary::arbitrary(&mut g)));
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
        let mut txs: Vec<Arc<Tx>> = Vec::with_capacity(30);
        let thread_rng = rand::thread_rng();
        let mut g = quickcheck::StdGen::new(thread_rng, 100);

        for _ in 0..30 {
            txs.push(Arc::new(quickcheck::Arbitrary::arbitrary(&mut g)));
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

    c.bench_function("deserialize 100", |b| {
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let id = Identity::new();
        let mut txs: Vec<Arc<Tx>> = Vec::with_capacity(100);
        let thread_rng = rand::thread_rng();
        let mut g = quickcheck::StdGen::new(thread_rng, 100);

        for _ in 0..100 {
            txs.push(Arc::new(quickcheck::Arbitrary::arbitrary(&mut g)));
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

    c.bench_function("deserialize 300", |b| {
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let id = Identity::new();
        let mut txs: Vec<Arc<Tx>> = Vec::with_capacity(300);
        let thread_rng = rand::thread_rng();
        let mut g = quickcheck::StdGen::new(thread_rng, 100);

        for _ in 0..300 {
            txs.push(Arc::new(quickcheck::Arbitrary::arbitrary(&mut g)));
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

    c.bench_function("deserialize 500", |b| {
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let id = Identity::new();
        let mut txs: Vec<Arc<Tx>> = Vec::with_capacity(500);
        let thread_rng = rand::thread_rng();
        let mut g = quickcheck::StdGen::new(thread_rng, 100);

        for _ in 0..500 {
            txs.push(Arc::new(quickcheck::Arbitrary::arbitrary(&mut g)));
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

    c.bench_function("deserialize 1000", |b| {
        let mut db = test_helpers::init_tempdb();
        let mut root = Hash::NULL_RLP;
        let mut trie = TrieDBMut::<BlakeDbHasher, Codec>::new(&mut db, &mut root);

        let id = Identity::new();
        let mut txs: Vec<Arc<Tx>> = Vec::with_capacity(1000);
        let thread_rng = rand::thread_rng();
        let mut g = quickcheck::StdGen::new(thread_rng, 100);

        for _ in 0..1000 {
            txs.push(Arc::new(quickcheck::Arbitrary::arbitrary(&mut g)));
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
