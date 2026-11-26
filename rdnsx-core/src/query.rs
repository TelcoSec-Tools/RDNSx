//! DNS query engine

use crate::hickory_ext::TxtExt;
use hickory_resolver::proto::dnssec::PublicKey;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use hickory_resolver::proto::dnssec::rdata::DNSSECRData;
use hickory_resolver::proto::rr::RData;
use tracing::trace;

use crate::error::Result;
use crate::resolver::ResolverPool;
use crate::types::{DnsRecord, RecordType, RecordValue, ResponseCode};

/// Full response to a DNS query
#[derive(Debug, Clone)]
pub struct QueryResponse {
    /// Name that was queried
    pub domain: String,
    /// Record type that was queried
    pub record_type: RecordType,
    /// DNS response code
    pub response_code: ResponseCode,
    /// Resolver that answered
    pub resolver: String,
    /// Time taken in milliseconds
    pub query_time_ms: f64,
    /// Answer records (may include CNAME chain records)
    pub records: Vec<DnsRecord>,
}

impl QueryResponse {
    /// Records to report: the answers, or one negative placeholder if there are none.
    pub fn into_records_or_negative(self) -> Vec<DnsRecord> {
        if self.records.is_empty() {
            vec![DnsRecord::negative(
                self.domain,
                self.record_type,
                self.response_code,
                self.resolver,
                self.query_time_ms,
            )]
        } else {
            self.records
        }
    }
}

/// DNS query engine
pub struct QueryEngine {
    resolver_pool: Arc<ResolverPool>,
}

impl QueryEngine {
    /// Create a new query engine
    pub fn new(resolver_pool: ResolverPool) -> Self {
        Self::from_shared(Arc::new(resolver_pool))
    }

    /// Create a query engine that shares an existing resolver pool
    pub fn from_shared(resolver_pool: Arc<ResolverPool>) -> Self {
        Self { resolver_pool }
    }

    /// The resolver pool used by this engine
    pub fn resolver_pool(&self) -> Arc<ResolverPool> {
        Arc::clone(&self.resolver_pool)
    }

    /// Query a domain for a specific record type.
    ///
    /// Returns only the records in the answer section; negative answers yield an
    /// empty vector. Use [`QueryEngine::query_response`] to see the response code.
    pub async fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<DnsRecord>> {
        Ok(self.query_response(domain, record_type).await?.records)
    }

    /// Query a domain and return the records together with the response code.
    pub async fn query_response(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<QueryResponse> {
        let start = Instant::now();
        let outcome = self.resolver_pool.query_full(domain, record_type).await?;
        let query_time_ms = start.elapsed().as_secs_f64() * 1000.0;

        let mut records = Vec::new();
        for record in outcome.lookup.answers() {
            trace!("Processing Record: {:?}", record);
            let value = parse_rdata(&record.data)?;
            // Label each record with its real owner name and type: a lookup for an
            // aliased name also returns the CNAME chain.
            let owner = record.name.to_string();
            let owner = owner.trim_end_matches('.').to_string();
            let rtype = RecordType::from_hickory(record.record_type()).unwrap_or(record_type);

            records.push(DnsRecord::new(
                owner,
                rtype,
                value,
                record.ttl,
                outcome.response_code,
                outcome.resolver.clone(),
                query_time_ms,
            ));
        }

        Ok(QueryResponse {
            domain: domain.to_string(),
            record_type,
            response_code: outcome.response_code,
            resolver: outcome.resolver,
            query_time_ms,
            records,
        })
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
            priority: mx.preference,
            exchange: mx.exchange.to_string(),
        }),
        RData::TXT(txt) => {
            // TXT records can have multiple strings, join them
            let text = txt
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes))
                .collect::<Vec<_>>()
                .join("");
            Ok(RecordValue::Text(text))
        }
        RData::SRV(srv) => Ok(RecordValue::Srv {
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
            target: srv.target.to_string(),
        }),
        RData::SOA(soa) => Ok(RecordValue::Soa {
            mname: soa.mname.to_string(),
            rname: soa.rname.to_string(),
            serial: soa.serial,
            refresh: soa.refresh,
            retry: soa.retry,
            expire: soa.expire,
            minimum: soa.minimum,
        }),
        RData::ANAME(dname) => Ok(RecordValue::Domain(dname.to_string())),
        RData::CAA(caa) => Ok(RecordValue::Caa {
            flags: caa.flags(),
            tag: caa.tag.as_str().to_string(),
            value: String::from_utf8_lossy(&caa.value).to_string(),
        }),
        RData::SSHFP(sshfp) => Ok(RecordValue::Sshfp {
            algorithm: sshfp.algorithm.into(),
            fingerprint_type: sshfp.fingerprint_type.into(),
            fingerprint: sshfp.fingerprint.to_vec(),
        }),
        RData::TLSA(tlsa) => Ok(RecordValue::Tlsa {
            cert_usage: tlsa.cert_usage.into(),
            selector: tlsa.selector.into(),
            matching_type: tlsa.matching.into(),
            cert_data: tlsa.cert_data.to_vec(),
        }),
        // RData::URI(uri) => Ok(RecordValue::Uri {
        //     priority: uri.priority(),
        //     weight: uri.weight(),
        //     target: String::from_utf8_lossy(uri.target()).to_string(),
        // }),
        RData::NAPTR(naptr) => Ok(RecordValue::Naptr {
            order: naptr.order,
            preference: naptr.preference,
            flags: String::from_utf8_lossy(&naptr.flags).to_string(),
            services: String::from_utf8_lossy(&naptr.services).to_string(),
            regexp: String::from_utf8_lossy(&naptr.regexp).to_string(),
            replacement: naptr.replacement.to_string(),
        }),
        RData::HINFO(hinfo) => Ok(RecordValue::Hinfo {
            cpu: String::from_utf8_lossy(&hinfo.cpu).to_string(),
            os: String::from_utf8_lossy(&hinfo.os).to_string(),
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
            if let Some(value) = decode_unknown(u16::from(*code), &raw.anything) {
                return Ok(value);
            }
            let hex = raw
                .anything
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            Ok(RecordValue::Other(format!(
                "TYPE{} \\# {} {}",
                u16::from(*code),
                raw.anything.len(),
                hex
            )))
        }
        RData::HTTPS(https) => Ok(RecordValue::Https {
            priority: https.svc_priority,
            target: https.target_name.to_string(),
            params: https
                .svc_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect(),
        }),
        RData::SVCB(svcb) => Ok(RecordValue::Svcb {
            priority: svcb.svc_priority,
            target: svcb.target_name.to_string(),
            params: svcb
                .svc_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect(),
        }),
        RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Ok(RecordValue::Dnskey {
            flags: key.flags(),
            protocol: 3,
            algorithm: u8::from(key.public_key().algorithm()),
            public_key: key.public_key().public_bytes().to_vec(),
        }),
        RData::DNSSEC(DNSSECRData::DS(ds)) => Ok(RecordValue::Ds {
            key_tag: ds.key_tag(),
            algorithm: u8::from(ds.algorithm()),
            digest_type: u8::from(ds.digest_type()),
            digest: ds.digest().to_vec(),
        }),
        // Everything else: use the presentation format
        _ => Ok(RecordValue::Other(rdata.to_string())),
    }
}

/// Decode record types hickory leaves as raw data: LOC (RFC 1876) and URI (RFC 7553)
fn decode_unknown(code: u16, data: &[u8]) -> Option<RecordValue> {
    let u32_at = |i: usize| -> Option<u32> {
        Some(u32::from_be_bytes(data.get(i..i + 4)?.try_into().ok()?))
    };
    match code {
        29 if data.len() == 16 && data[0] == 0 => Some(RecordValue::Loc {
            version: data[0],
            size: data[1],
            horiz_pre: data[2],
            vert_pre: data[3],
            latitude: u32_at(4)?,
            longitude: u32_at(8)?,
            altitude: u32_at(12)?,
        }),
        256 if data.len() >= 4 => Some(RecordValue::Uri {
            priority: u16::from_be_bytes([data[0], data[1]]),
            weight: u16::from_be_bytes([data[2], data[3]]),
            target: String::from_utf8_lossy(&data[4..]).to_string(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    #[test]
    fn decodes_uri() {
        let mut data = vec![0, 10, 0, 1];
        data.extend_from_slice(b"sip:alice@example.com");
        assert_eq!(
            decode_unknown(256, &data).unwrap().to_string(),
            "10 1 sip:alice@example.com"
        );
    }

    #[test]
    fn decodes_loc() {
        // 51.5 N, 0.25 W, 10 m
        let lat = (1u64 << 31) + (51.5 * 3_600_000.0) as u64;
        let lon = (1u64 << 31) - (0.25 * 3_600_000.0) as u64;
        let alt = 100_000 * 100 + 1000;
        let mut data = vec![0, 0x12, 0x16, 0x13];
        data.extend_from_slice(&(lat as u32).to_be_bytes());
        data.extend_from_slice(&(lon as u32).to_be_bytes());
        data.extend_from_slice(&(alt as u32).to_be_bytes());
        assert_eq!(
            decode_unknown(29, &data).unwrap().to_string(),
            "51.500000 -0.250000 10.00m"
        );
    }
}
