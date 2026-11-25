//! Deterministic tests against an in-process DNS server (no network needed)

mod support;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::proto::rr::RecordType as HRecordType;
use rdnsx_core::config::DnsxOptions;
use rdnsx_core::dnssec_analysis::DnssecAnalyzer;
use rdnsx_core::{
    DnsEnumerator, DnsxClient, RecordType, RecordValue, ResolverPool, ResponseCode, WildcardFilter,
};
use support::{name, spawn, MockZone};

const ZONE: &str = "rdnsx.test.";

fn zone() -> MockZone {
    let mut zone = MockZone::new(ZONE)
        .a("ns1.rdnsx.test.", [127, 0, 0, 1])
        .a("web.rdnsx.test.", [192, 0, 2, 10])
        .cname("www.rdnsx.test.", "web.rdnsx.test.")
        .txt("rdnsx.test.", "v=spf1 -all")
        .txt("_dmarc.rdnsx.test.", "v=DMARC1; p=reject")
        .txt(
            "selector1._domainkey.rdnsx.test.",
            "v=DKIM1; k=rsa; p=MIGfMA0",
        )
        .nsec(
            "rdnsx.test.",
            "_dmarc.rdnsx.test.",
            vec![HRecordType::SOA, HRecordType::NS, HRecordType::TXT],
        )
        .nsec(
            "_dmarc.rdnsx.test.",
            "ns1.rdnsx.test.",
            vec![HRecordType::TXT],
        )
        .nsec("ns1.rdnsx.test.", "web.rdnsx.test.", vec![HRecordType::A])
        .nsec("web.rdnsx.test.", "www.rdnsx.test.", vec![HRecordType::A])
        .nsec("www.rdnsx.test.", "rdnsx.test.", vec![HRecordType::CNAME]);
    zone.wildcard = Some((name("wild.rdnsx.test."), "198.51.100.7".parse().unwrap()));
    zone.servfail = vec![name("broken.rdnsx.test.")];
    zone.allow_axfr = true;
    zone
}

fn options(servers: &[SocketAddr]) -> DnsxOptions {
    DnsxOptions {
        resolvers: servers.iter().map(|s| s.to_string()).collect(),
        timeout: Duration::from_secs(2),
        retries: 1,
        concurrency: 10,
        rate_limit: 0,
    }
}

async fn client() -> (DnsxClient, SocketAddr) {
    let addr = spawn(zone()).await;
    (DnsxClient::with_options(options(&[addr])).unwrap(), addr)
}

#[tokio::test]
async fn reports_nxdomain() {
    let (client, _) = client().await;
    let response = client
        .query_response("missing.rdnsx.test", RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code, ResponseCode::NxDomain);
    assert!(response.records.is_empty());

    let negative = response.into_records_or_negative();
    assert_eq!(negative.len(), 1);
    assert!(negative[0].is_negative());
    assert_eq!(negative[0].to_string(), "missing.rdnsx.test [NXDOMAIN]");
}

#[tokio::test]
async fn reports_nodata_as_noerror() {
    let (client, _) = client().await;
    let response = client
        .query_response("web.rdnsx.test", RecordType::Mx)
        .await
        .unwrap();
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert!(response.records.is_empty());
}

#[tokio::test]
async fn reports_servfail() {
    let (client, _) = client().await;
    let response = client
        .query_response("broken.rdnsx.test", RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn servfail_fails_over_to_next_resolver() {
    let mut bad = zone();
    bad.servfail.push(name("web.rdnsx.test."));
    let bad = spawn(bad).await;
    let good = spawn(zone()).await;
    let client = DnsxClient::with_options(options(&[bad, good])).unwrap();

    // Round-robin starts on a different resolver each time; both must succeed
    for _ in 0..2 {
        let response = client
            .query_response("web.rdnsx.test", RecordType::A)
            .await
            .unwrap();
        assert_eq!(response.response_code, ResponseCode::NoError);
        assert_eq!(response.records.len(), 1);
        assert_eq!(response.resolver, good.to_string());
    }
}

#[tokio::test]
async fn labels_cname_chain_records_with_owner_and_type() {
    let (client, _) = client().await;
    let records = client.query("www.rdnsx.test", RecordType::A).await.unwrap();

    let cname = records
        .iter()
        .find(|r| r.record_type == RecordType::Cname)
        .expect("CNAME in chain");
    assert_eq!(cname.domain, "www.rdnsx.test");
    assert_eq!(
        cname.value,
        RecordValue::Domain("web.rdnsx.test.".to_string())
    );

    let a = records
        .iter()
        .find(|r| r.record_type == RecordType::A)
        .expect("A record");
    assert_eq!(a.domain, "web.rdnsx.test");
    assert_eq!(a.value, RecordValue::Ip("192.0.2.10".parse().unwrap()));
}

#[tokio::test]
async fn zone_transfer_against_explicit_server() {
    let addr = spawn(zone()).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let enumerator = DnsEnumerator::new(pool);

    let result = enumerator
        .zone_transfer("rdnsx.test", &[addr.to_string()])
        .await
        .unwrap();
    assert_eq!(result.successful_transfers.len(), 1);
    assert!(result
        .records
        .iter()
        .any(|r| r.domain == "web.rdnsx.test" && r.record_type == RecordType::A));
    assert!(result
        .records
        .iter()
        .any(|r| r.record_type == RecordType::Soa));
}

#[tokio::test]
async fn zone_transfer_refused_is_reported() {
    let mut locked = zone();
    locked.allow_axfr = false;
    let addr = spawn(locked).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let enumerator = DnsEnumerator::new(pool);

    let result = enumerator
        .zone_transfer("rdnsx.test", &[addr.to_string()])
        .await
        .unwrap();
    assert!(result.successful_transfers.is_empty());
    assert_eq!(result.failed_transfers.len(), 1);
    assert!(
        result.failed_transfers[0].1.contains("REFUSED")
            || result.failed_transfers[0].1.contains("Refused")
    );
}

#[tokio::test]
async fn walks_the_nsec_chain() {
    let addr = spawn(zone()).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let analyzer = DnssecAnalyzer::new(pool);

    let result = analyzer
        .zone_walking_with_server("rdnsx.test", addr, 100)
        .await
        .unwrap();
    assert!(result.enumeration_successful);
    assert_eq!(result.denial_type, "NSEC");
    assert_eq!(
        result.discovered_names,
        vec![
            "rdnsx.test",
            "_dmarc.rdnsx.test",
            "ns1.rdnsx.test",
            "web.rdnsx.test",
            "www.rdnsx.test"
        ]
    );
    assert_eq!(result.stop_reason, "Walked the complete chain");
}

#[tokio::test]
async fn zone_walk_respects_limit() {
    let addr = spawn(zone()).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let analyzer = DnssecAnalyzer::new(pool);

    let result = analyzer
        .zone_walking_with_server("rdnsx.test", addr, 2)
        .await
        .unwrap();
    assert_eq!(result.discovered_names.len(), 2);
    assert!(result.stop_reason.contains("limit"));
}

#[tokio::test]
async fn wildcard_filter_drops_only_wildcard_answers() {
    let addr = spawn(zone()).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let client = DnsxClient::from_pool(Arc::clone(&pool));
    let filter = WildcardFilter::new(Some("rdnsx.test".to_string()), Arc::clone(&pool), 0);

    assert!(filter.test_wildcard("wild.rdnsx.test").await.unwrap());
    assert!(!filter.test_wildcard("rdnsx.test").await.unwrap());

    let mut records = client
        .query("anything.wild.rdnsx.test", RecordType::A)
        .await
        .unwrap();
    records.extend(client.query("web.rdnsx.test", RecordType::A).await.unwrap());
    assert_eq!(records.len(), 2);

    let kept = filter.filter_by_ip(records).await.unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].domain, "web.rdnsx.test");
}

#[tokio::test]
async fn finds_spf_dmarc_and_dkim() {
    let addr = spawn(zone()).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let enumerator = DnsEnumerator::new(pool);

    let result = enumerator
        .email_security_enumeration("rdnsx.test")
        .await
        .unwrap();
    assert_eq!(result.dkim_selectors.len(), 1);
    assert_eq!(result.dkim_selectors[0].selector, "selector1");
    assert!(result.dkim_selectors[0].record.contains("p=MIGfMA0"));
}

#[tokio::test]
async fn fingerprints_a_server() {
    let addr = spawn(zone()).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let enumerator = DnsEnumerator::new(pool);

    let fp = enumerator
        .server_fingerprinting_for_zone(&addr.to_string(), Some("rdnsx.test"))
        .await
        .unwrap();
    assert_eq!(fp.version_bind.as_deref(), Some("mock-dns 1.0"));
    assert!(fp.edns_support);
    assert!(fp.tcp_support);
    assert!(!fp.recursion_available);
    assert_eq!(fp.address.as_deref(), Some(addr.to_string().as_str()));
}

#[tokio::test]
async fn rate_limit_spaces_queries() {
    let addr = spawn(zone()).await;
    let mut opts = options(&[addr]);
    opts.rate_limit = 20; // 50 ms between queries
    let client = DnsxClient::with_options(opts).unwrap();

    let start = std::time::Instant::now();
    for _ in 0..5 {
        client.query("web.rdnsx.test", RecordType::A).await.unwrap();
    }
    assert!(
        start.elapsed() >= Duration::from_millis(200),
        "took {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn bruteforce_finds_names_and_skips_wildcards() {
    use rdnsx_core::Bruteforcer;

    let addr = spawn(zone()).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let client = Arc::new(DnsxClient::from_pool(Arc::clone(&pool)));

    let found = Bruteforcer::new(Arc::clone(&client), 4)
        .enumerate_with_records("rdnsx.test", "web,www,nope", "FUZZ", RecordType::A)
        .await
        .unwrap();
    let mut names: Vec<_> = found.iter().map(|(n, _)| n.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["web.rdnsx.test", "www.rdnsx.test"]);

    let filter = WildcardFilter::new(Some("wild.rdnsx.test".to_string()), Arc::clone(&pool), 0);
    let found = Bruteforcer::new(client, 4)
        .with_wildcard_filter(filter)
        .enumerate_with_records("wild.rdnsx.test", "a,b,c", "FUZZ", RecordType::A)
        .await
        .unwrap();
    assert!(
        found.is_empty(),
        "wildcard answers should be filtered: {:?}",
        found
    );
}

#[test]
fn negative_record_value_is_empty() {
    assert_eq!(RecordValue::Empty.to_string(), "");
    let _: IpAddr = "192.0.2.1".parse().unwrap();
}

#[tokio::test]
async fn zone_walk_crosses_delegations() {
    let zone = MockZone::new("deleg.test.")
        .a("a.deleg.test.", [192, 0, 2, 1])
        .a("www.deleg.test.", [192, 0, 2, 2])
        .delegate("sub.deleg.test.", "ns.elsewhere.test.")
        .nsec(
            "deleg.test.",
            "a.deleg.test.",
            vec![HRecordType::SOA, HRecordType::NS],
        )
        .nsec("a.deleg.test.", "sub.deleg.test.", vec![HRecordType::A])
        .nsec("sub.deleg.test.", "www.deleg.test.", vec![HRecordType::NS])
        .nsec("www.deleg.test.", "deleg.test.", vec![HRecordType::A]);
    let addr = spawn(zone).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let analyzer = DnssecAnalyzer::new(pool);

    let result = analyzer
        .zone_walking_with_server("deleg.test", addr, 100)
        .await
        .unwrap();
    assert_eq!(result.stop_reason, "Walked the complete chain");
    assert_eq!(
        result.discovered_names,
        vec!["deleg.test", "a.deleg.test", "sub.deleg.test", "www.deleg.test"]
    );
}

#[tokio::test]
async fn synthesized_nsec_is_not_walked() {
    let mut next = hickory_resolver::proto::rr::Name::from_labels(vec![
        vec![0u8],
        b"synth".to_vec(),
        b"test".to_vec(),
    ])
    .unwrap();
    next.set_fqdn(true);
    let zone = MockZone::new("synth.test.").nsec_to(
        "synth.test.",
        next,
        vec![HRecordType::SOA, HRecordType::NS],
    );
    let addr = spawn(zone).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let analyzer = DnssecAnalyzer::new(pool);

    let result = analyzer
        .zone_walking_with_server("synth.test", addr, 100)
        .await
        .unwrap();
    assert!(!result.enumeration_successful);
    assert_eq!(result.denial_type, "NSEC (synthesized)");
    assert!(result.discovered_names.is_empty());
}

#[tokio::test]
async fn partial_zone_transfer_is_flagged() {
    let mut z = zone();
    z.truncate_axfr = true;
    let addr = spawn(z).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let enumerator = DnsEnumerator::new(pool);

    let result = enumerator
        .zone_transfer("rdnsx.test", &[addr.to_string()])
        .await
        .unwrap();
    assert_eq!(result.successful_transfers.len(), 1);
    assert_eq!(result.incomplete_transfers.len(), 1);
    assert!(!result.complete);
    assert!(!result.records.is_empty());
}

#[tokio::test]
async fn complete_zone_transfer_is_marked_complete() {
    let addr = spawn(zone()).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let enumerator = DnsEnumerator::new(pool);
    let result = enumerator
        .zone_transfer("rdnsx.test", &[addr.to_string()])
        .await
        .unwrap();
    assert!(result.complete);
    assert!(result.incomplete_transfers.is_empty());
}

#[tokio::test]
async fn wildcard_cname_chains_are_filtered() {
    let mut z = zone().a("edge.cdn.rdnsx.test.", [203, 0, 113, 9]);
    z.wildcard_cname = Some((name("cw.rdnsx.test."), name("edge.cdn.rdnsx.test.")));
    let addr = spawn(z).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let client = DnsxClient::from_pool(Arc::clone(&pool));
    let filter = WildcardFilter::new(Some("rdnsx.test".to_string()), Arc::clone(&pool), 2);

    let mut records = client
        .query("candidate.cw.rdnsx.test", RecordType::A)
        .await
        .unwrap();
    assert_eq!(records.len(), 2, "CNAME plus A: {:?}", records);
    records.extend(client.query("web.rdnsx.test", RecordType::A).await.unwrap());

    let kept = filter.filter_by_ip(records).await.unwrap();
    assert_eq!(kept.len(), 1, "{:?}", kept);
    assert_eq!(kept[0].domain, "web.rdnsx.test");
}

#[tokio::test]
async fn wildcard_analysis_reports_uncovered_types() {
    let addr = spawn(zone()).await;
    let pool = Arc::new(ResolverPool::new(&options(&[addr])).unwrap());
    let enumerator = DnsEnumerator::new(pool);

    let analysis = enumerator.wildcard_analysis("wild.rdnsx.test").await.unwrap();
    assert!(analysis.has_wildcard);
    // The mock wildcard only covers A, so the other types tell hosts apart
    assert!(!analysis.bypass_attempts.is_empty());
    assert!(analysis.bypass_attempts.iter().all(|a| a.success));
}
