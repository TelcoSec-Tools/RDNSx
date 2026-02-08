//! Unit tests for RDNSx core

use std::time::{Duration, SystemTime};

use crate::types::{DnsRecord, RecordType, RecordValue, ResponseCode};

#[test]
fn test_record_type_display() {
    assert_eq!(format!("{}", RecordType::A), "A");
    assert_eq!(format!("{}", RecordType::Aaaa), "AAAA");
    assert_eq!(format!("{}", RecordType::Caa), "CAA");
    assert_eq!(format!("{}", RecordType::Mx), "MX");
    assert_eq!(format!("{}", RecordType::Txt), "TXT");
}

#[test]
fn test_record_type_hickory_conversion() {
    // Test a few key conversions
    assert_eq!(RecordType::A.to_hickory(), hickory_resolver::proto::rr::RecordType::A);
    assert_eq!(RecordType::Aaaa.to_hickory(), hickory_resolver::proto::rr::RecordType::AAAA);
    assert_eq!(RecordType::Caa.to_hickory(), hickory_resolver::proto::rr::RecordType::CAA);
    assert_eq!(RecordType::Mx.to_hickory(), hickory_resolver::proto::rr::RecordType::MX);
}

#[test]
fn test_dns_record_creation() {
    let record = DnsRecord::new(
        "example.com".to_string(),
        RecordType::A,
        RecordValue::Ip("127.0.0.1".parse().unwrap()),
        300,
        ResponseCode::NoError,
        "8.8.8.8:53".to_string(),
        42.5,
    );

    assert_eq!(record.domain, "example.com");
    assert_eq!(record.record_type, RecordType::A);
    assert_eq!(record.ttl, 300);
    assert_eq!(record.response_code, ResponseCode::NoError);
    assert_eq!(record.resolver, "8.8.8.8:53");
    assert_eq!(record.query_time_ms, 42.5);
}

#[test]
fn test_record_value_to_string() {
    let ip_value = RecordValue::Ip("127.0.0.1".parse().unwrap());
    assert_eq!(ip_value.to_string(), "127.0.0.1");

    let domain_value = RecordValue::Domain("example.com".to_string());
    assert_eq!(domain_value.to_string(), "example.com");

    let text_value = RecordValue::Text("Hello World".to_string());
    assert_eq!(text_value.to_string(), "Hello World");

    let other_value = RecordValue::Other("Custom data".to_string());
    assert_eq!(other_value.to_string(), "Custom data");
}

#[test]
fn test_response_code_display() {
    assert_eq!(format!("{}", ResponseCode::NoError), "NOERROR");
    assert_eq!(format!("{}", ResponseCode::NxDomain), "NXDOMAIN");
    assert_eq!(format!("{}", ResponseCode::ServFail), "SERVFAIL");
}

#[test]
fn test_caa_record_value() {
    let caa_value = RecordValue::Caa {
        flags: 0,
        tag: "issue".to_string(),
        value: "letsencrypt.org".to_string(),
    };
    assert_eq!(caa_value.to_string(), "0 issue letsencrypt.org");
}