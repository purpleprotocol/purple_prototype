//#![feature(test)]

#[macro_use]
extern crate criterion;
extern crate mimalloc;
extern crate persistence;
extern crate rand;
extern crate rocksdb;
extern crate tempdir;

use criterion::Criterion;
use mimalloc::MiMalloc;
use persistence::PersistentDb;
use rand::Rng;
use rocksdb::{Options, DB};
use std::sync::Arc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("default options flush no cf - 10 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let wal_path = path.join("wal");
        let db = Arc::new(DB::open_default(path.to_str().unwrap()).unwrap());
        let mut per_db = PersistentDb::new(db, None);
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.flush());
    });

    c.bench_function("default options flush no cf - 100 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let db = Arc::new(DB::open_default(path.to_str().unwrap()).unwrap());
        let mut per_db = PersistentDb::new(db, None);
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.flush());
    });

    c.bench_function("default options flush no cf - 1000 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let db = Arc::new(DB::open_default(path.to_str().unwrap()).unwrap());
        let mut per_db = PersistentDb::new(db, None);
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.flush());
    });

    c.bench_function("default options flush no cf - 10000 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let db = Arc::new(DB::open_default(path.to_str().unwrap()).unwrap());
        let mut per_db = PersistentDb::new(db, None);
        let mut rng = rand::thread_rng();

        for _ in 0..10000 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.flush());
    });

    c.bench_function("default options flush with cf - 10 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = Arc::new(DB::open_cf(&opts, path.to_str().unwrap(), &["test_cf"]).unwrap());
        let mut per_db = PersistentDb::new(db, Some("test_cf"));
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.flush());
    });

    c.bench_function("default options flush with cf - 100 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = Arc::new(DB::open_cf(&opts, path.to_str().unwrap(), &["test_cf"]).unwrap());
        let mut per_db = PersistentDb::new(db, Some("test_cf"));
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.flush());
    });

    c.bench_function("default options flush with cf - 1000 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = Arc::new(DB::open_cf(&opts, path.to_str().unwrap(), &["test_cf"]).unwrap());
        let mut per_db = PersistentDb::new(db, Some("test_cf"));
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.flush());
    });

    c.bench_function("default options flush with cf - 10000 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = Arc::new(DB::open_cf(&opts, path.to_str().unwrap(), &["test_cf"]).unwrap());
        let mut per_db = PersistentDb::new(db, Some("test_cf"));
        let mut rng = rand::thread_rng();

        for _ in 0..10000 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.flush());
    });

    c.bench_function("custom options flush with cf - 100 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let wal_path = path.join("wal");
        let opts = persistence::db_options(&wal_path);
        let db = Arc::new(DB::open_cf(&opts, path.to_str().unwrap(), &["test_cf"]).unwrap());
        let mut per_db = PersistentDb::new(db, Some("test_cf"));
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.flush());
    });

    c.bench_function("custom options flush with cf - 1000 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let wal_path = path.join("wal");
        let opts = persistence::db_options(&wal_path);
        let db = Arc::new(DB::open_cf(&opts, path.to_str().unwrap(), &["test_cf"]).unwrap());
        let mut per_db = PersistentDb::new(db, Some("test_cf"));
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.flush());
    });

    c.bench_function("custom options flush with cf - 10000 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let wal_path = path.join("wal");
        let opts = persistence::db_options(&wal_path);
        let db = Arc::new(DB::open_cf(&opts, path.to_str().unwrap(), &["test_cf"]).unwrap());
        let mut per_db = PersistentDb::new(db, Some("test_cf"));
        let mut rng = rand::thread_rng();

        for _ in 0..10000 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.flush());
    });

    c.bench_function("clone 100 unflushed items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let wal_path = path.join("wal");
        let opts = persistence::db_options(&wal_path);
        let db = Arc::new(DB::open_cf(&opts, path.to_str().unwrap(), &["test_cf"]).unwrap());
        let mut per_db = PersistentDb::new(db, Some("test_cf"));
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.clone());
    });

    c.bench_function("clone 500 unflushed items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let wal_path = path.join("wal");
        let opts = persistence::db_options(&wal_path);
        let db = Arc::new(DB::open_cf(&opts, path.to_str().unwrap(), &["test_cf"]).unwrap());
        let mut per_db = PersistentDb::new(db, Some("test_cf"));
        let mut rng = rand::thread_rng();

        for _ in 0..500 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.clone());
    });

    c.bench_function("clone 1000 unflushed items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let wal_path = path.join("wal");
        let opts = persistence::db_options(&wal_path);
        let db = Arc::new(DB::open_cf(&opts, path.to_str().unwrap(), &["test_cf"]).unwrap());
        let mut per_db = PersistentDb::new(db, Some("test_cf"));
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.clone());
    });

    c.bench_function("clone 10000 unflushed items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
        let wal_path = path.join("wal");
        let opts = persistence::db_options(&wal_path);
        let db = Arc::new(DB::open_cf(&opts, path.to_str().unwrap(), &["test_cf"]).unwrap());
        let mut per_db = PersistentDb::new(db, Some("test_cf"));
        let mut rng = rand::thread_rng();

        for _ in 0..10000 {
            let key: [u8; 32] = rng.gen();
            let val: [u8; 32] = rng.gen();
            per_db.put(&key, &val);
        }

        b.iter(|| per_db.clone());
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
