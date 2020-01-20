/*
  Copyright (C) 2018-2020 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/

#![allow(unused)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate jsonrpc_macros;

#[macro_use(slog_error, slog_info, slog_trace, slog_log, slog_o)] 
extern crate slog;

#[cfg(any(feature = "miner-cpu", feature = "miner-gpu", feature = "miner-cpu-avx", feature = "miner-test-mode"))]
extern crate reqwest;

extern crate account;
extern crate chain;
extern crate clap;
extern crate crypto;
extern crate dirs;
extern crate elastic_array;
extern crate slog_stdlog;
extern crate slog_envlogger;
extern crate slog_term;
extern crate slog_scope;
extern crate slog_async;
extern crate futures;
extern crate hashdb;
extern crate itc;
extern crate jsonrpc_core;
extern crate jump;
extern crate network;
extern crate parking_lot;
extern crate persistence;
extern crate rocksdb;
extern crate tokio;
extern crate miner;
extern crate mempool;

use slog::Drain;
use clap::{App, Arg};
use crypto::{Identity, NodeId, SecretKey as Sk};
use elastic_array::ElasticArray128;
use futures::future::ok;
use futures::sync::mpsc::channel;
use futures::Future;
use hashdb::HashDB;
use parking_lot::RwLock;
use mempool::Mempool;
use network::bootstrap::cache::BootstrapCache;
use network::*;
use persistence::PersistentDb;
use tokio::runtime::{Runtime, Builder};
use std::thread;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::net::IpAddr;
use std::str::FromStr;

#[cfg(not(feature = "mimalloc-allocator"))]
use std::alloc::System;

#[cfg(not(feature = "mimalloc-allocator"))]
#[global_allocator]
static GLOBAL: System = System;

#[cfg(feature = "mimalloc-allocator")]
extern crate mimalloc;

#[cfg(feature = "mimalloc-allocator")]
use mimalloc::MiMalloc;

#[cfg(feature = "mimalloc-allocator")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const DEFAULT_NETWORK_NAME: &'static str = "purple-testnet";
const BOOTNODES: &'static [&'static str] = &[
    "95.179.130.222:44034",
    "45.32.111.18:44034",
];

fn main() {
    let drain =
        slog_async::Async::default(
        slog_envlogger::new(
        slog_term::CompactFormat::new(
            slog_term::TermDecorator::new()
            .stderr().build()
            ).build().fuse()
        ));

    let root_logger = slog::Logger::root(drain.fuse(),
                                         slog_o!("build" => "8jdkj2df", "version" => "0.1.5"));

    let _guard = slog_envlogger::init().unwrap();

    slog_scope::scope(
        &root_logger,
        || {}
    );

    let argv = parse_cli_args();
    let storage_path = get_storage_path(&argv.network_name);
    let db_path = storage_path.join("database");
    let bootstrap_cache_path = storage_path.join("bootstrap_cache");

    // Wipe database
    if argv.wipe {
        info!("Deleting database...");
        fs::remove_dir_all(&db_path).unwrap();
        info!("Database deleted!");
    }

    info!("Initializing database...");

    let storage_db_path = db_path.join("node_storage");
    let pow_chain_db_path = db_path.join("pow_chain_db");
    let state_db_path = db_path.join("state_db");
    let bootstrap_cache_db_path = bootstrap_cache_path.join("bootstrap_cache_db"); 

    let storage_wal_path = db_path.join("node_storage_wal");
    let pow_chain_wal_path = db_path.join("pow_chain_db_wal");
    let state_wal_path = db_path.join("state_db_wal");
    let bootstrap_cache_wal_path = bootstrap_cache_path.join("bootstrap_cache_db_wal");

    let storage_db = Arc::new(persistence::open_database(
        &storage_db_path,
        &storage_wal_path,
    ));
    let pow_chain_db = Arc::new(persistence::open_database(
        &pow_chain_db_path,
        &pow_chain_wal_path,
    ));
    let state_db = Arc::new(persistence::open_database(
        &state_db_path,
        &state_wal_path,
    ));
    let bootstrap_cache_db = Arc::new(persistence::open_database(
        &bootstrap_cache_db_path,
        &bootstrap_cache_wal_path,
    ));
    let mut node_storage = PersistentDb::new(storage_db, None);
    let pow_chain_db = PersistentDb::new(pow_chain_db, None);
    let state_db = PersistentDb::new(state_db, None);
    let bootstrap_cache_db = PersistentDb::new(bootstrap_cache_db, None);
    let bootstrap_cache = BootstrapCache::new(bootstrap_cache_db, argv.bootstrap_cache_size);

    let pow_chain =
        chain::init(pow_chain_db, state_db, argv.archival_mode);

    info!("Database initialization was successful!");

    let mempool: Option<Arc<RwLock<Mempool>>> = if argv.no_mempool {
        None
    } else {
        info!("Initializing mempool...");
        let main_cur_hash = crypto::hash_slice(transactions::MAIN_CUR_NAME).to_short();
        let mempool = Arc::new(RwLock::new(Mempool::new(pow_chain.clone(), argv.mempool_size, vec![main_cur_hash], 80)));
        info!("Mempool initialization was successful!");

        Some(mempool)
    };

    let (pow_tx, pow_rx) = channel(10000);

    info!("Setting up the network...");

    let (node_id, skey) = fetch_credentials(&mut node_storage);
    let accept_connections = Arc::new(AtomicBool::new(true));

    // Set up runtime
    let mut runtime = Builder::new()
        .blocking_threads(10)
        .name_prefix("purple-runtime-")
        // Unwind all panics
        .panic_handler(|err| std::panic::resume_unwind(err))
        .build()
        .unwrap();

    #[cfg(any(feature = "miner-cpu", feature = "miner-gpu", feature = "miner-cpu-avx", feature = "miner-test-mode"))]
    let (our_ip, mut runtime) = {
        debug!("Retrieving external ip...");

        // Retrieve our ip
        let (our_ip, runtime) = fetch_ip(runtime);
        let our_ip = SocketAddr::new(our_ip, argv.port);

        debug!("Successfully retrieved external ip address {}", our_ip);
        (our_ip, runtime)
    };

    #[cfg(any(feature = "miner-cpu", feature = "miner-gpu", feature = "miner-cpu-avx", feature = "miner-test-mode"))]
    let network = Network::new(
        node_id,
        argv.port,
        argv.network_name.to_owned(),
        skey,
        argv.max_peers,
        pow_tx,
        pow_chain.clone(),
        bootstrap_cache,
        mempool,
        accept_connections.clone(),
        Some(our_ip),
    );

    #[cfg(not(any(feature = "miner-cpu", feature = "miner-gpu", feature = "miner-cpu-avx", feature = "miner-test-mode")))]
    let network = Network::new(
        node_id,
        argv.port,
        argv.network_name.to_owned(),
        skey,
        argv.max_peers,
        pow_tx,
        pow_chain.clone(),
        bootstrap_cache,
        mempool,
        accept_connections.clone(),
        None,
    );

    // Start the tokio runtime
    runtime.spawn(ok(()).and_then(move |_| {
        // Start listening for blocks
        start_block_listeners(network.clone(), pow_chain.clone(), pow_rx);

        // Start listening to connections
        start_listener(network.clone(), accept_connections.clone());

        // Start bootstrap process
        bootstrap(
            network.clone(),
            accept_connections,
            node_storage.clone(),
            argv.max_peers,
            argv.bootnodes.clone(),
            argv.port,
            true,
        );

        // Start miner related jobs
        #[cfg(any(feature = "miner-cpu", feature = "miner-gpu", feature = "miner-cpu-avx", feature = "miner-test-mode"))]
        {
            if argv.start_mining {
                #[cfg(feature = "miner-test-mode")]
                let proof_delay = Some(argv.proof_delay);

                #[cfg(not(feature = "miner-test-mode"))]
                let proof_delay = None;

                // Start mining
                crate::jobs::start_miner(pow_chain, network.clone(), our_ip, proof_delay).expect("Could not start miner");
            }
        }

        Ok(())
    }));

    // Block the current thread
    runtime.shutdown_on_idle()
        .wait().unwrap();
}

#[cfg(any(feature = "miner-cpu", feature = "miner-gpu", feature = "miner-cpu-avx", feature = "miner-test-mode"))]
/// Returns our ip address
fn fetch_ip(mut runtime: Runtime) -> (IpAddr, Runtime) {
    let fut = reqwest::async::Client::new()
        .get("https://api.ipify.org?format=json")
        .send()
        .and_then(|mut resp| resp.json());

    let resp: HashMap<String, String> = runtime.block_on(fut).expect("Could not retrieve external ip address! Please re-start the core to try again!");
    let ip_str = resp.get("ip").expect("Could not parse external ip address! Please re-start the core to try again!");
    let ip = IpAddr::from_str(&ip_str).expect("Could not parse external ip address! Please re-start the core to try again!");

    (ip, runtime)
}

// Fetch stored node id or create new identity and store it
fn fetch_credentials(db: &mut PersistentDb) -> (NodeId, Sk) {
    let node_id_key = crypto::hash_slice(b"node_id");
    let node_skey_key = crypto::hash_slice(b"node_skey");

    match (db.get(&node_id_key), db.get(&node_skey_key)) {
        (Some(id), Some(skey)) => {
            let mut id_buf = [0; 32];
            let mut skey_buf = [0; 64];

            id_buf.copy_from_slice(&id);
            skey_buf.copy_from_slice(&skey);

            (NodeId::new(id_buf), Sk(skey_buf))
        }
        _ => {
            // Create new identity and write keys to database
            let identity = Identity::new();

            let bin_pkey = identity.pkey().0;
            let bin_skey = identity.skey().0;

            db.emplace(node_id_key, ElasticArray128::<u8>::from_slice(&bin_pkey));
            db.emplace(node_skey_key, ElasticArray128::<u8>::from_slice(&bin_skey));

            (NodeId::new(bin_pkey), identity.skey().clone())
        }
    }
}

fn get_storage_path(network_name: &str) -> PathBuf {
    Path::new(&dirs::home_dir().unwrap())
        .join("purple")
        .join(network_name)
}

struct Argv {
    network_name: String,
    bootnodes: Vec<SocketAddr>,
    mempool_size: u64,
    port: u16,
    bootstrap_cache_size: u64,
    max_peers: usize,
    no_mempool: bool,
    interactive: bool,
    archival_mode: bool,
    wipe: bool,

    #[cfg(any(feature = "miner-cpu", feature = "miner-gpu", feature = "miner-cpu-avx", feature = "miner-test-mode"))]
    start_mining: bool,

    #[cfg(feature = "miner-test-mode")]
    proof_delay: u32,
}

fn parse_cli_args() -> Argv {
    let argv = App::new(format!("Purple Protocol v{}", env!("CARGO_PKG_VERSION")))
        .arg(
            Arg::with_name("network_name")
                .long("network-name")
                .value_name("NETWORK_NAME")
                .help("The name of the network")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mempool_size")
                .long("mempool-size")
                .value_name("MEMPOOL_SIZE")
                .help("The maximum number of transactions that the mempool is allowed to store")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("bootstrap_cache_size")
                .long("bootstrap-cache-size")
                .value_name("SIZE")
                .help("The maximum allowed size of the bootstrap cache for this node. The bootstrap cache stores ip addresses of previously encountered peers making us connect faster to the network.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("no_mempool")
                .long("no-mempool")
                .conflicts_with("mempool_size")
                .help("Start the node without a mempool")
        )
        .arg(
            Arg::with_name("no_rpc")
                .long("no-rpc")
                .help("Start the node without the json-rpc interface")
        )
        .arg(
            Arg::with_name("no_bootnodes")
                .long("no-bootnodes")
                .help("Start the node without attempting to connect to any bootnode")
        )
        .arg(
            Arg::with_name("bootnodes")
                .long("bootnodes")
                .value_name("IP_ADDRESES")
                .min_values(1)
                .conflicts_with("no_bootnodes")
                .help("A list of bootnodes to initially connect to")
        )
        .arg(
            Arg::with_name("interactive")
                .long("interactive")
                .short("i")
                .help("Start the node in interactive mode")
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .short("p")
                .help("The port to listen on for incoming connections. Default is 44034")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("max_peers")
                .long("max-peers")
                .value_name("MAX_PEERS")
                .help("The maximum number of allowed peer connections. Default is 8")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("wipe")
                .long("wipe")
                .help("Wipe the database before starting the node, forcing it to re-sync"),
        )
        .arg(
            Arg::with_name("prune")
                .long("prune")
                .help("Whether to prune the ledger or to keep the entire transaction history. False by default"),
        );

    #[cfg(any(feature = "miner-cpu", feature = "miner-gpu", feature = "miner-cpu-avx", feature = "miner-test-mode"))]
    let argv = {
        // Miner only flags
        argv
            .arg(
                Arg::with_name("start_mining")
                    .long("start-mining")
                    .help("Start the node as a miner node")
            )
    };

    #[cfg(feature = "miner-test-mode")]
    let argv = {
        // Miner test mode only flags
        argv
            .arg(
                Arg::with_name("proof_delay")
                    .long("proof-delay")
                    .value_name("MILLISECONDS")
                    .help("The time to wait before sending a valid proof. Only used in test mode!")
                    .takes_value(true),
            )
    };

    let matches = argv.get_matches();

    let network_name: String = if let Some(arg) = matches.value_of("network_name") {
        unwrap!(arg.parse(), "Expected value for <NETWORK_NAME>")
    } else {
        DEFAULT_NETWORK_NAME.to_owned()
    };

    let mempool_size: u64 = if let Some(arg) = matches.value_of("mempool_size") {
        unwrap!(arg.parse(), "Bad value for <MEMPOOL_SIZE>")
    } else {
        700000
    };

    let port: u16 = if let Some(arg) = matches.value_of("port") {
        unwrap!(arg.parse(), "Bad value for <PORT>")
    } else {
        44034
    };

    let bootstrap_cache_size: u64 = if let Some(arg) = matches.value_of("bootstrap_cache_size") {
        unwrap!(arg.parse(), "Bad value for <SIZE>")
    } else {
        1000000
    };

    let max_peers: usize = if let Some(arg) = matches.value_of("max_peers") {
        unwrap!(arg.parse(), "Bad value for <MAX_PEERS>")
    } else {
        8
    };

    let bootnodes: Vec<SocketAddr> = if let Some(bootnodes) = matches.values_of("bootnodes") {
        bootnodes
            .map(|addr| unwrap!(addr.parse(), "Bad value for <IP_ADDRESSES>"))
            .collect()
    } else {
        BOOTNODES.iter().map(|addr| addr.parse().unwrap()).collect()
    };

    #[cfg(feature = "miner-test-mode")]
    let proof_delay: u32 = if let Some(arg) = matches.value_of("proof_delay") {
        unwrap!(arg.parse(), "Bad value for <MILLISECONDS>")
    } else {
        1
    };

    let archival_mode: bool = !matches.is_present("prune");
    let no_mempool: bool = matches.is_present("no_mempool");
    let interactive: bool = matches.is_present("interactive");
    let wipe: bool = matches.is_present("wipe");
    let no_bootnodes: bool = matches.is_present("no_bootnodes");
    let bootnodes = if no_bootnodes { Vec::new() } else { bootnodes };

    #[cfg(any(feature = "miner-cpu", feature = "miner-gpu", feature = "miner-cpu-avx", feature = "miner-test-mode"))]
    let start_mining: bool = matches.is_present("start_mining");

    Argv {
        bootnodes,
        network_name,
        bootstrap_cache_size,
        max_peers,
        no_mempool,
        interactive,
        mempool_size,
        archival_mode,
        wipe,
        port,

        #[cfg(any(feature = "miner-cpu", feature = "miner-gpu", feature = "miner-cpu-avx", feature = "miner-test-mode"))]
        start_mining,

        #[cfg(feature = "miner-test-mode")]
        proof_delay
    }
}

mod jobs;