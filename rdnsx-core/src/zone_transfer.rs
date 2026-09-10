//! DNS zone transfer (AXFR) enumeration

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode as HResponseCode};
use hickory_resolver::proto::rr::{Name, RecordType as HRecordType, DNSClass};
use hickory_resolver::proto::serialize::binary::{BinDecoder, BinDecodable, BinEncoder, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::error::{DnsxError, Result};
use crate::resolver::ResolverPool;
use crate::types::{DnsRecord, RecordType};

use serde::{Deserialize, Serialize};

/// Results from zone transfer enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransferResult {
    pub domain: String,
    pub successful_transfers: Vec<String>,
    pub failed_transfers: Vec<(String, String)>,
    pub records: Vec<DnsRecord>,
}

/// Zone transfer enumeration functionality
pub struct ZoneTransferEnumerator {
    resolver_pool: Arc<ResolverPool>,
}

impl ZoneTransferEnumerator {
    /// Create a new zone transfer enumerator
    pub fn new(resolver_pool: Arc<ResolverPool>) -> Self {
        Self { resolver_pool }
    }

    /// Attempt DNS zone transfer (AXFR) against specified servers
    pub async fn enumerate(&self, domain: &str, nameservers: &[String]) -> Result<ZoneTransferResult> {
        info!("Attempting zone transfer for domain: {}", domain);

        let mut results = ZoneTransferResult {
            domain: domain.to_string(),
            successful_transfers: Vec::new(),
            failed_transfers: Vec::new(),
            records: Vec::new(),
        };

        for ns in nameservers {
            match self.attempt_axfr(domain, ns).await {
                Ok(records) => {
                    info!("✅ Zone transfer successful from {}: {} records", ns, records.len());
                    results.successful_transfers.push(ns.clone());
                    results.records.extend(records);
                }
                Err(e) => {
                    debug!("❌ Zone transfer failed from {}: {}", ns, e);
                    results.failed_transfers.push((ns.clone(), e.to_string()));
                }
            }
        }

        Ok(results)
    }

    /// Attempt AXFR against a specific nameserver over TCP port 53
    async fn attempt_axfr(&self, domain: &str, nameserver: &str) -> Result<Vec<DnsRecord>> {
        // Resolve target socket address
        let (host, port) = if let Some((h, p)) = nameserver.split_once(':') {
            (h, p.parse::<u16>().unwrap_or(53))
        } else {
            (nameserver, 53)
        };

        let target_ip = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            ip
        } else {
            let ips = self.resolver_pool.lookup_ipv4(host).await?;
            if ips.is_empty() {
                return Err(DnsxError::Other(format!("Failed to resolve nameserver host: {}", host)));
            }
            std::net::IpAddr::V4(ips[0])
        };

        let addr = SocketAddr::new(target_ip, port);
        debug!("Connecting to {} for AXFR on {}", addr, domain);

        let mut stream = match timeout(std::time::Duration::from_secs(10), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(DnsxError::Other(format!("TCP connection to {} failed: {}", addr, e))),
            Err(_) => return Err(DnsxError::Other(format!("TCP connection to {} timed out", addr))),
        };

        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(false);

        let mut name = Name::from_str(domain)
            .map_err(|e| DnsxError::invalid_input(format!("Invalid domain name {}: {}", domain, e)))?;
        if !name.is_fqdn() {
            name = name.append_domain(&Name::root())
                .map_err(|e| DnsxError::invalid_input(format!("Failed to make FQDN: {}", e)))?;
        }

        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(HRecordType::AXFR);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);

        let mut buf = Vec::new();
        {
            let mut encoder = BinEncoder::new(&mut buf);
            message.emit(&mut encoder)
                .map_err(|e| DnsxError::Other(format!("Failed to encode AXFR message: {}", e)))?;
        }

        let len = (buf.len() as u16).to_be_bytes();
        stream.write_all(&len).await
            .map_err(|e| DnsxError::Other(format!("Failed to send AXFR length: {}", e)))?;
        stream.write_all(&buf).await
            .map_err(|e| DnsxError::Other(format!("Failed to send AXFR query: {}", e)))?;

        let mut all_records = Vec::new();
        let mut soa_count = 0;

        let transfer_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);

        // Loop reading responses until AXFR is complete (second SOA or end of stream)
        loop {
            if tokio::time::Instant::now() >= transfer_deadline {
                if !all_records.is_empty() {
                    break;
                } else {
                    return Err(DnsxError::Other("AXFR transfer exceeded overall time budget".to_string()));
                }
            }

            let mut len_buf = [0u8; 2];
            let read_len = timeout(std::time::Duration::from_secs(10), stream.read_exact(&mut len_buf)).await;
            let resp_len = match read_len {
                Ok(Ok(_)) => u16::from_be_bytes(len_buf) as usize,
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof && !all_records.is_empty() => break,
                Ok(Err(e)) => return Err(DnsxError::Other(format!("Error reading AXFR response length: {}", e))),
                Err(_) => {
                    if !all_records.is_empty() {
                        break;
                    } else {
                        return Err(DnsxError::Other("Timeout reading AXFR response length".to_string()));
                    }
                }
            };

            let mut resp_buf = vec![0u8; resp_len];
            if let Err(e) = timeout(std::time::Duration::from_secs(10), stream.read_exact(&mut resp_buf)).await {
                if !all_records.is_empty() {
                    break;
                } else {
                    return Err(DnsxError::Other(format!("Timeout reading AXFR response payload: {}", e)));
                }
            }

            let mut decoder = BinDecoder::new(&resp_buf);
            let response = Message::read(&mut decoder)
                .map_err(|e| DnsxError::Other(format!("Failed to decode AXFR response: {}", e)))?;

            let rcode = response.response_code();
            if rcode != HResponseCode::NoError {
                return Err(DnsxError::Other(format!("Zone transfer refused or failed: RCODE {}", rcode)));
            }

            let answers = response.answers();
            if answers.is_empty() && all_records.is_empty() {
                return Err(DnsxError::Other("Zone transfer returned 0 records (empty answer)".to_string()));
            }

            for record in answers {
                let rtype = match record.record_type() {
                    HRecordType::A => RecordType::A,
                    HRecordType::AAAA => RecordType::Aaaa,
                    HRecordType::CNAME => RecordType::Cname,
                    HRecordType::MX => RecordType::Mx,
                    HRecordType::TXT => RecordType::Txt,
                    HRecordType::NS => RecordType::Ns,
                    HRecordType::SOA => {
                        soa_count += 1;
                        RecordType::Soa
                    }
                    HRecordType::SRV => RecordType::Srv,
                    HRecordType::PTR => RecordType::Ptr,
                    HRecordType::CAA => RecordType::Caa,
                    _ => continue,
                };

                if let Some(rdata) = record.data() {
                    if let Ok(val) = crate::query::parse_rdata(rdata) {
                        let dns_rec = DnsRecord::new(
                            record.name().to_string(),
                            rtype,
                            val,
                            record.ttl(),
                            crate::ResponseCode::NoError,
                            nameserver.to_string(),
                            0.0,
                        );
                        all_records.push(dns_rec);
                    }
                }
            }

            // In standard AXFR, the transfer begins with SOA and terminates after the second SOA
            if soa_count >= 2 {
                break;
            }
        }

        if all_records.is_empty() {
            return Err(DnsxError::Other("Zone transfer not allowed or no records found".to_string()));
        }

        Ok(all_records)
    }
}