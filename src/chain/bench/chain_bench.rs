#[macro_use]
extern crate criterion;
extern crate miner;
extern crate rocksdb;
extern crate tempdir;

use account::normal::NormalAddress;
use chain::*;
use chrono::prelude::*;
use constants::*;
use criterion::Criterion;
use crypto::*;
use miner::Proof;
use parking_lot::RwLock;
use patricia_trie::TrieDBMut;
use persistence::{Codec, DbHasher, PersistentDb};
use rand::prelude::*;
use rocksdb::DB;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use transactions::*;
use triomphe::Arc;

pub fn random_socket_addr() -> SocketAddr {
    let mut thread_rng = rand::thread_rng();
    let i1 = thread_rng.gen();
    let i2 = thread_rng.gen();
    let i3 = thread_rng.gen();
    let i4 = thread_rng.gen();

    let addr = IpAddr::V4(Ipv4Addr::new(i1, i2, i3, i4));
    SocketAddr::new(addr, 44034)
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("append_block with a CheckpointBlock", |b| {
        let db1 = test_helpers::init_tempdb();
        let db2 = test_helpers::init_tempdb();
        chain::init(db1, db2, true);

        let db3 = test_helpers::init_tempdb();
        let chain = Chain::<PowBlock>::new(db3, PowBlock::genesis_state(), true);
        let mut chain = ChainRef::<PowBlock>::new(Arc::new(RwLock::new(chain)));

        let proof = Proof::test_proof(42);
        let collector_address = NormalAddress::random();
        let ip = random_socket_addr();
        let height = 0;

        let identity = Identity::new();
        let node_id = NodeId(*identity.pkey());

        let mut block = CheckpointBlock::new(
            chain.canonical_tip().block_hash().unwrap(),
            collector_address,
            ip,
            height + 1,
            proof,
            node_id,
        );

        block.sign_miner(identity.skey());
        block.compute_hash();

        let block = Arc::new(block);
        let block = PowBlock::Checkpoint(block);
        let block = Arc::new(block);

        b.iter(|| chain.append_block(block.clone()));
    });

    c.bench_function("append_block with a CheckpointBlock - flush to disk", |b| {
        let db1 = test_helpers::init_tempdb();
        let db2 = test_helpers::init_tempdb();
        chain::init(db1, db2, true);

        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let db3 = Arc::new(DB::open_default(path.to_str().unwrap()).unwrap());
        let per_db = PersistentDb::new(db3, None);

        let chain = Chain::<PowBlock>::new(per_db, PowBlock::genesis_state(), true);
        let chain = ChainRef::<PowBlock>::new(Arc::new(RwLock::new(chain)));

        let proof = Proof::test_proof(42);
        let collector_address = NormalAddress::random();
        let ip = random_socket_addr();
        let height = 0;

        let identity = Identity::new();
        let node_id = NodeId(*identity.pkey());

        let mut block = CheckpointBlock::new(
            chain.canonical_tip().block_hash().unwrap(),
            collector_address,
            ip,
            height + 1,
            proof,
            node_id,
        );

        block.sign_miner(identity.skey());
        block.compute_hash();

        let block = Arc::new(block);
        let block = PowBlock::Checkpoint(block);
        let block = Arc::new(block);

        b.iter(|| chain.append_block(block.clone()));
    });

    c.bench_function("append_block with an empty TransactionBlock", |b| {
        let db1 = test_helpers::init_tempdb();
        let db2 = test_helpers::init_tempdb();
        chain::init(db1, db2, true);

        let db3 = test_helpers::init_tempdb();
        let chain = Chain::<PowBlock>::new(db3, PowBlock::genesis_state(), true);
        let chain = ChainRef::<PowBlock>::new(Arc::new(RwLock::new(chain)));
        let proof = Proof::test_proof(42);
        let identity = Identity::new();
        let node_id = NodeId(*identity.pkey());
        let collector_address = NormalAddress::random();
        let ip = random_socket_addr();
        let mut height = 1;

        let mut checkpoint_block = CheckpointBlock::new(
            chain.canonical_tip().block_hash().unwrap(),
            collector_address,
            ip,
            height,
            proof,
            node_id.clone(),
        );

        checkpoint_block.sign_miner(identity.skey());
        checkpoint_block.compute_hash();

        let mut blocks = Vec::new();
        let mut parent_hash = checkpoint_block.block_hash().unwrap();
        for _ in 0..ALLOWED_TXS_BLOCKS {
            height += 1;

            let mut block = TransactionBlock {
                tx_checksums: Some(Vec::<ShortHash>::new()),
                pieces_sizes: Some(Vec::<usize>::new()),
                height,
                parent_hash,
                state_root: Some(chain.get_state_root()),
                tx_root: Some(ShortHash::NULL_RLP),
                hash: None,
                miner_id: node_id.clone(),
                miner_signature: None,
                timestamp: Utc::now(),
                transactions: Some(Arc::new(RwLock::new(Vec::new()))),
            };
            block.sign_miner(identity.skey());
            block.compute_hash();

            let block = Arc::<TransactionBlock>::new(block);
            let block = PowBlock::Transaction(block);
            let block = Arc::<PowBlock>::new(block);

            parent_hash = block.block_hash().unwrap();

            blocks.push(block);
        }

        b.iter(|| {
            let db3 = test_helpers::init_tempdb();
            let chain = Chain::<PowBlock>::new(db3, PowBlock::genesis_state(), true);
            let chain = ChainRef::<PowBlock>::new(Arc::new(RwLock::new(chain)));

            let checkpoint_block = checkpoint_block.clone();
            let blocks = blocks.clone();
            let block = Arc::<CheckpointBlock>::new(checkpoint_block);
            let block = PowBlock::Checkpoint(block);
            let block = Arc::<PowBlock>::new(block);

            chain.append_block(block).unwrap();

            for block in blocks {
                chain.append_block(block).unwrap();
            }
        });
    });

    c.bench_function("append_block with a full TransactionBlock", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path1 = tmp_dir.path().join("1");
        let path2 = tmp_dir.path().join("2");

        let db1 = Arc::new(DB::open_default(path1.to_str().unwrap()).unwrap());
        let per_db = PersistentDb::new(db1, None);

        let db2 = Arc::new(DB::open_default(path2.to_str().unwrap()).unwrap());
        let db_state = PersistentDb::new(db2, None);

        crate::init(per_db.clone(), db_state, true);

        let chain = Chain::<PowBlock>::new(per_db, PowBlock::genesis_state(), true);
        let chain = ChainRef::<PowBlock>::new(Arc::new(RwLock::new(chain)));
        let proof = Proof::test_proof(42);
        let identity = Identity::new();
        let node_id = NodeId(*identity.pkey());
        let collector_address = NormalAddress::random();
        let ip = random_socket_addr();
        let mut height = 1;

        let mut checkpoint_block = CheckpointBlock::new(
            chain.canonical_tip().block_hash().unwrap(),
            collector_address,
            ip,
            height,
            proof,
            node_id.clone(),
        );

        checkpoint_block.sign_miner(identity.skey());
        checkpoint_block.compute_hash();

        let mut blocks = Vec::new();
        let mut parent_hash = checkpoint_block.block_hash().unwrap();
        let (mut db, mut state) = chain.get_db_and_state_root();

        // {
        //     let mut trie = TrieDBMut::<DbHasher, Codec>::from_existing(&mut db, &mut state).unwrap();
        //     set_account_balance(TestAccount::A.to_perm_address().as_bytes(), 10000000, &mut trie);
        // }

        for _ in 0..ALLOWED_TXS_BLOCKS {
            height += 1;

            let transaction_list = get_tx_list_of_size(MAX_TX_SET_SIZE).unwrap();
            let state_root = {
                // apply all transactions in the list to the state in order to get the state root
                {
                    let mut trie =
                        TrieDBMut::<DbHasher, Codec>::from_existing(&mut db, &mut state).unwrap();

                    for tx in transaction_list.iter() {
                        tx.apply(&mut trie);
                    }
                }
                state
            };

            let mut block = TransactionBlock {
                tx_checksums: Some(Vec::<ShortHash>::new()),
                pieces_sizes: Some(Vec::<usize>::new()),
                height,
                parent_hash,
                state_root: Some(state_root),
                tx_root: Some(ShortHash::NULL_RLP),
                hash: None,
                miner_id: node_id.clone(),
                miner_signature: None,
                timestamp: Utc::now(),
                transactions: Some(Arc::new(RwLock::new(transaction_list))),
            };
            block.sign_miner(identity.skey());
            block.compute_hash();

            let block = Arc::<TransactionBlock>::new(block);
            let block = PowBlock::Transaction(block);
            let block = Arc::<PowBlock>::new(block);

            parent_hash = block.block_hash().unwrap();

            blocks.push(block);
        }

        println!("st");

        b.iter(|| {
            println!("b1");
            let db = test_helpers::init_tempdb();
            println!("b2");
            let chain = Chain::<PowBlock>::new(db, PowBlock::genesis_state(), true);
            println!("b3");
            let chain = ChainRef::<PowBlock>::new(Arc::new(RwLock::new(chain)));

            println!("b4");
            let checkpoint_block = checkpoint_block.clone();
            let blocks = blocks.clone();
            let block = Arc::<CheckpointBlock>::new(checkpoint_block);
            let block = PowBlock::Checkpoint(block);
            let block = Arc::<PowBlock>::new(block);

            println!("dst1");
            chain.append_block(block).unwrap();

            println!("dst2");
            for block in blocks {
                println!("app1");
                chain.append_block(block).unwrap();
                println!("app2");
            }
            println!("dn3");
        });
    });

    // c.bench_function("append_block with a full TransactionBlock", |b| {
    //     let db1 = test_helpers::init_tempdb();
    //     let db2 = test_helpers::init_tempdb();
    //     chain::init(db1, db2, true);

    //     let db3 = test_helpers::init_tempdb();
    //     let chain = Chain::<PowBlock>::new(db3, PowBlock::genesis_state(), true);
    //     let chain = ChainRef::<PowBlock>::new(Arc::new(RwLock::new(chain)));
    //     let proof = Proof::test_proof(42);
    //     let identity = Identity::new();
    //     let node_id = NodeId(*identity.pkey());
    //     let collector_address = NormalAddress::random();
    //     let ip = random_socket_addr();
    //     let mut height = 1;

    //     let mut checkpoint_block = CheckpointBlock::new(
    //         chain.canonical_tip().block_hash().unwrap(),
    //         collector_address,
    //         ip,
    //         height,
    //         proof,
    //         node_id.clone(),
    //     );

    //     checkpoint_block.sign_miner(identity.skey());
    //     checkpoint_block.compute_hash();

    //     let mut blocks = Vec::new();
    //     let mut parent_hash = checkpoint_block.block_hash().unwrap();
    //     for _ in 0..ALLOWED_TXS_BLOCKS {
    //         height += 1;

    //         let transaction_list = get_tx_list_of_size(MAX_TX_SET_SIZE).unwrap();

    //         let mut block = TransactionBlock {
    //             tx_checksums: Some(Vec::<ShortHash>::new()),
    //             pieces_sizes: Some(Vec::<usize>::new()),
    //             height: height,
    //             parent_hash: parent_hash,
    //             state_root: Some(chain.get_state_root()),
    //             tx_root: Some(ShortHash::NULL_RLP),
    //             hash: None,
    //             miner_id: node_id.clone(),
    //             miner_signature: None,
    //             timestamp: Utc::now(),
    //             transactions: Some(Arc::new(RwLock::new(transaction_list))),
    //         };

    //         block.sign_miner(identity.skey());
    //         block.compute_hash();

    //         let block = Arc::<TransactionBlock>::new(block);
    //         let block = PowBlock::Transaction(block);
    //         let block = Arc::<PowBlock>::new(block);

    //         parent_hash = block.block_hash().unwrap();

    //         blocks.push(block);
    //     }

    //     b.iter(|| {
    //         let db3 = test_helpers::init_tempdb();
    //         let chain = Chain::<PowBlock>::new(db3, PowBlock::genesis_state(), true);
    //         let chain = ChainRef::<PowBlock>::new(Arc::new(RwLock::new(chain)));

    //         let checkpoint_block = checkpoint_block.clone();
    //         let blocks = blocks.clone();
    //         let block = Arc::<CheckpointBlock>::new(checkpoint_block);
    //         let block = PowBlock::Checkpoint(block);
    //         let block = Arc::<PowBlock>::new(block);

    //         chain.append_block(block).unwrap();

    //         for block in blocks {
    //             chain.append_block(block).unwrap();
    //         }
    //     });
    // });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
