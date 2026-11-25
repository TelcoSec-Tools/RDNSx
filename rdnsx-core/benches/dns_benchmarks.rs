//! Offline micro-benchmarks (no network access needed)

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use hickory_resolver::proto::rr::rdata::{A, TXT};
use hickory_resolver::proto::rr::RData;
use rdnsx_core::cache::{CacheKey, DnsCache};
use rdnsx_core::query::parse_rdata;
use rdnsx_core::{DnsRecord, RecordType, RecordValue, ResponseCode};

fn bench_parse_rdata(c: &mut Criterion) {
    let a_record = RData::A(A(Ipv4Addr::new(192, 168, 1, 1)));
    let txt_record = RData::TXT(
        TXT::try_new(std::iter::once(
            b"v=spf1 include:_spf.example.com -all".to_vec(),
        ))
        .unwrap(),
    );

    c.bench_function("parse_rdata_a", |b| {
        b.iter(|| parse_rdata(black_box(&a_record)))
    });
    c.bench_function("parse_rdata_txt", |b| {
        b.iter(|| parse_rdata(black_box(&txt_record)))
    });
}

fn bench_cache(c: &mut Criterion) {
    let cache = DnsCache::new(10_000, Duration::from_secs(300));
    let record = DnsRecord::new(
        "www.example.com".to_string(),
        RecordType::A,
        RecordValue::Ip("93.184.216.34".parse().unwrap()),
        300,
        ResponseCode::NoError,
        "8.8.8.8:53".to_string(),
        1.0,
    );
    for i in 0..1000 {
        cache.put(
            CacheKey::new(format!("host{}.example.com", i), RecordType::A),
            vec![record.clone()],
            None,
        );
    }

    c.bench_function("cache_hit", |b| {
        let key = CacheKey::new("host500.example.com", RecordType::A);
        b.iter(|| cache.get(black_box(&key)))
    });
    c.bench_function("cache_miss", |b| {
        let key = CacheKey::new("missing.example.com", RecordType::A);
        b.iter(|| cache.get(black_box(&key)))
    });
}

criterion_group!(benches, bench_parse_rdata, bench_cache);
criterion_main!(benches);
