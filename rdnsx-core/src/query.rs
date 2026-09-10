//! DNS query engine

use std::net::IpAddr;
use std::time::Instant;

use hickory_resolver::proto::rr::RData;
use tracing::debug;

use crate::error::Result;
use crate::resolver::ResolverPool;
use crate::types::{DnsRecord, RecordType, RecordValue, ResponseCode};

/// DNS query engine
pub struct QueryEngine {
    resolver_pool: ResolverPool,
}

impl QueryEngine {
    /// Create a new query engine
    pub fn new(resolver_pool: ResolverPool) -> Self {
        Self { resolver_pool }
    }

    /// Query a domain for a specific record type
    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<DnsRecord>> {
        let start = Instant::now();
        let (lookup, resolver_addr) = self.resolver_pool.query(domain, record_type).await?;

        let query_time_ms = start.elapsed().as_secs_f64() * 1000.0;
        // Lookup represents successful queries, so assume NOERROR
        let response_code = ResponseCode::NoError;

        let mut records = Vec::new();
        debug!("Processing {} records from lookup", lookup.iter().count());

        // Extract records from lookup
        for record in lookup.records() {
            debug!("Processing Record: {:?}", record);
            if let Some(rdata) = record.data() {
                let value = parse_rdata(rdata)?;
                let ttl = record.ttl();

                records.push(DnsRecord::new(
                    domain.to_string(),
                    record_type,
                    value,
                    ttl,
                    response_code,
                    resolver_addr.clone(),
                    query_time_ms,
                ));
            }
        }

        Ok(records)
    }

    /// Lookup A records and return IP addresses
    pub async fn lookup_ipv4(&self, domain: &str) -> Result<Vec<std::net::Ipv4Addr>> {
        self.resolver_pool.lookup_ipv4(domain).await
    }

    /// Lookup AAAA records and return IP addresses
    pub async fn lookup_ipv6(&self, domain: &str) -> Result<Vec<std::net::Ipv6Addr>> {
        self.resolver_pool.lookup_ipv6(domain).await
    }
}

/// Parse RData into RecordValue
pub fn parse_rdata(rdata: &RData) -> Result<RecordValue> {
    match rdata {
        RData::A(ipv4) => Ok(RecordValue::Ip(IpAddr::V4(**ipv4))),
        RData::AAAA(ipv6) => Ok(RecordValue::Ip(IpAddr::V6(**ipv6))),
        RData::CNAME(cname) => Ok(RecordValue::Domain(cname.to_string())),
        RData::PTR(ptr) => Ok(RecordValue::Domain(ptr.to_string())),
        RData::NS(ns) => Ok(RecordValue::Domain(ns.to_string())),
        RData::MX(mx) => Ok(RecordValue::Mx {
            priority: mx.preference(),
            exchange: mx.exchange().to_string(),
        }),
        RData::TXT(txt) => {
            // TXT records can have multiple strings, join them
            let text = txt.iter()
                .map(|bytes| String::from_utf8_lossy(bytes))
                .collect::<Vec<_>>()
                .join("");
            Ok(RecordValue::Text(text))
        }
        RData::SRV(srv) => Ok(RecordValue::Srv {
            priority: srv.priority(),
            weight: srv.weight(),
            port: srv.port(),
            target: srv.target().to_string(),
        }),
        RData::SOA(soa) => Ok(RecordValue::Soa {
            mname: soa.mname().to_string(),
            rname: soa.rname().to_string(),
            serial: soa.serial(),
            refresh: soa.refresh(),
            retry: soa.retry(),
            expire: soa.expire(),
            minimum: soa.minimum(),
        }),
        RData::ANAME(dname) => Ok(RecordValue::Domain(dname.to_string())),
        RData::CAA(caa) => Ok(RecordValue::Caa {
            flags: if caa.issuer_critical() { 128 } else { 0 },
            tag: caa.tag().as_str().to_string(),
            value: format!("{}", caa.value()),
        }),
        RData::SSHFP(sshfp) => Ok(RecordValue::Sshfp {
            algorithm: sshfp.algorithm().into(),
            fingerprint_type: sshfp.fingerprint_type().into(),
            fingerprint: sshfp.fingerprint().to_vec(),
        }),
        RData::TLSA(tlsa) => Ok(RecordValue::Tlsa {
            cert_usage: tlsa.cert_usage().into(),
            selector: tlsa.selector().into(),
            matching_type: tlsa.matching().into(),
            cert_data: tlsa.cert_data().to_vec(),
        }),
        // RData::URI(uri) => Ok(RecordValue::Uri {
        //     priority: uri.priority(),
        //     weight: uri.weight(),
        //     target: String::from_utf8_lossy(uri.target()).to_string(),
        // }),
        RData::NAPTR(naptr) => Ok(RecordValue::Naptr {
            order: naptr.order(),
            preference: naptr.preference(),
            flags: String::from_utf8_lossy(naptr.flags()).to_string(),
            services: String::from_utf8_lossy(naptr.services()).to_string(),
            regexp: String::from_utf8_lossy(naptr.regexp()).to_string(),
            replacement: naptr.replacement().to_string(),
        }),
        RData::HINFO(hinfo) => Ok(RecordValue::Hinfo {
            cpu: String::from_utf8_lossy(hinfo.cpu()).to_string(),
            os: String::from_utf8_lossy(hinfo.os()).to_string(),
        }),
        // RData::LOC(loc) => Ok(RecordValue::Loc {
        //     version: loc.version(),
        //     size: loc.size(),
        //     horiz_pre: loc.horiz_pre(),
        //     vert_pre: loc.vert_pre(),
        //     latitude: loc.latitude(),
        //     longitude: loc.longitude(),
        //     altitude: loc.altitude(),
        // }),
        RData::Unknown { code, rdata: raw } => {
            let hex = raw.anything().iter().map(|b| format!("{:02x}", b)).collect::<String>();
            Ok(RecordValue::Other(format!("TYPE{} \\# {} {}", u16::from(*code), raw.anything().len(), hex)))
        }
        // For complex records we don't fully parse yet, return as Other
        _ => Ok(RecordValue::Other(format!("{:?}", rdata))),
    }
}
