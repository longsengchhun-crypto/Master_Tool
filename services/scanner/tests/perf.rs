//! Measurement harness (not a benchmark suite): records real timings on the machine it runs on, against real ClamAV.
//! #[ignore]d; run with the same env as the engine suite:
//!   SENTRIX_CLAMAV_DIR=... SENTRIX_DATA_DIR=... cargo test --release -p sentrix-core --test perf -- --ignored --nocapture --test-threads=1
//! Numbers are only meaningful for the machine/OS state they were taken on; do not quote them elsewhere.

use sentrix_core::clamav::ClamEngine;
use sentrix_core::{Limits, ScanOptions, Scanner, Verdict};
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

#[test]
#[ignore = "measurement; needs real ClamAV"]
fn measure() {
    let clam = Arc::new(ClamEngine::new(std::env::var_os("SENTRIX_CLAMAV_DIR").expect("SENTRIX_CLAMAV_DIR"), std::env::var_os("SENTRIX_DATA_DIR").expect("SENTRIX_DATA_DIR")));
    let t = Instant::now();
    clam.start().expect("clamd");
    println!("clamd start (signature load): {:.1}s", t.elapsed().as_secs_f64());
    let scanner = Scanner::new(Limits::default(), Some(clam.clone()));
    let dir = tempfile::tempdir().unwrap();

    // 1. Many small files.
    const N: usize = 3000;
    for i in 0..N {
        let sub = dir.path().join(format!("d{}", i % 20));
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(format!("f{i}.txt")), format!("sample document number {i}\n").repeat(40)).unwrap();
    }
    let opts = ScanOptions { use_cache: false, ..Default::default() };
    let t = Instant::now();
    let b = scanner.scan_paths(&[dir.path().to_path_buf()], &opts, 2, &|_| {}, &|_| {});
    let cold = t.elapsed().as_secs_f64();
    assert_eq!(b.counts.total, N);
    assert_eq!(b.counts.clean, N, "{:?}", b.counts);
    println!("{N} small files (~1 KB), 2 workers, no cache: {cold:.2}s = {:.0} files/s", N as f64 / cold);

    let cached = ScanOptions::default();
    scanner.scan_paths(&[dir.path().to_path_buf()], &cached, 2, &|_| {}, &|_| {}); // prime
    let t = Instant::now();
    let b = scanner.scan_paths(&[dir.path().to_path_buf()], &cached, 2, &|_| {}, &|_| {});
    let warm = t.elapsed().as_secs_f64();
    assert_eq!(b.counts.clean, N);
    println!("{N} small files, unchanged, cache hits: {warm:.2}s = {:.0} files/s", N as f64 / warm);

    // 2. One large file (random, so nothing short-circuits).
    let big = dir.path().join("big.bin");
    {
        let mut f = std::fs::File::create(&big).unwrap();
        let mut chunk = vec![0u8; 1 << 20];
        let mut x: u64 = 0x9E3779B97F4A7C15;
        for _ in 0..256 {
            for b in chunk.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = x as u8;
            }
            f.write_all(&chunk).unwrap();
        }
    }
    let t = Instant::now();
    let r = scanner.scan_file(&big, &opts);
    let secs = t.elapsed().as_secs_f64();
    println!("1 file of 256 MiB random data: {secs:.2}s = {:.0} MiB/s, verdict {:?}, complete {}", 256.0 / secs, r.verdict, r.complete);
    assert!(matches!(r.verdict, Verdict::Clean | Verdict::UnableToVerify));

    // 3. A file over the in-memory analysis limit is still handled (streamed hash, engine only) and reported partial.
    let small_limits = Scanner::new(Limits { max_analyze_bytes: 64 << 20, ..Limits::default() }, Some(clam.clone()));
    let t = Instant::now();
    let r = small_limits.scan_file(&big, &opts);
    println!("same file with a 64 MiB analysis limit (streamed): {:.2}s, verdict {:?}, complete {}", t.elapsed().as_secs_f64(), r.verdict, r.complete);

    clam.stop();
}
