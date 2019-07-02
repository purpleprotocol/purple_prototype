#![feature(test)]

#[macro_use]
extern crate criterion;
extern crate persistence;
extern crate rocksdb;
extern crate tempdir;
extern crate rand;
extern crate mimalloc;

use mimalloc::MiMalloc;
use criterion::Criterion;
use rocksdb::{Options, DB};
use rand::Rng;
use std::sync::Arc;
use persistence::PersistentDb;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("default options flush no cf - 10 items", |b| {
        let tmp_dir = tempdir::TempDir::new("db_dir").unwrap();
        let path = tmp_dir.path();
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
        let opts = persistence::db_options();
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
        let opts = persistence::db_options();
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
        let opts = persistence::db_options();
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
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);