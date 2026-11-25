//! Direct DNS queries to a specific server.
//!
//! The resolver pool goes through recursive resolvers and only exposes answer
//! records. Some research techniques need the whole message (flags, authority
//! section, EDNS) from a chosen server, usually an authoritative nameserver.
//! This module sends single queries over UDP, retrying over TCP when the answer
//! is truncated.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, RecordType as HRecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::error::{DnsxError, Result};
use crate::resolver::ResolverPool;
use crate::types::RecordType;

/// Options for a raw query
#[derive(Debug, Clone, Copy)]
pub struct RawQueryOptions {
    /// Set the RD (recursion desired) flag
    pub recursion_desired: bool,
    /// Send an EDNS(0) OPT record
    pub edns: bool,
    /// Set the DO (DNSSEC OK) bit; implies `edns`
    pub dnssec_ok: bool,
    /// DNS class (IN unless probing CHAOS names such as version.bind)
    pub class: DNSClass,
    /// Per-attempt timeout
    pub timeout: Duration,
}

impl Default for RawQueryOptions {
    fn default() -> Self {
        Self {
            recursion_desired: false,
            edns: true,
            dnssec_ok: false,
            class: DNSClass::IN,
            timeout: Duration::from_secs(5),
        }
    }
}

/// Parse a name, making it fully qualified
pub fn fqdn(name: &str) -> Result<Name> {
    let mut parsed = Name::from_str(name)
        .map_err(|e| DnsxError::invalid_input(format!("Invalid domain name {}: {}", name, e)))?;
    if !parsed.is_fqdn() {
        parsed = parsed
            .append_domain(&Name::root())
            .map_err(|e| DnsxError::invalid_input(format!("Failed to make FQDN: {}", e)))?;
    }
    Ok(parsed)
}

fn build_query(name: &Name, rtype: HRecordType, opts: &RawQueryOptions) -> Message {
    let mut message = Message::new();
    message.set_id(rand::random());
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(opts.recursion_desired);

    let mut query = Query::query(name.clone(), rtype);
    query.set_query_class(opts.class);
    message.add_query(query);

    if opts.edns || opts.dnssec_ok {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(opts.dnssec_ok);
        message.set_edns(edns);
    }
    message
}

/// Send one query to `server` and return the full response message.
pub async fn raw_query(
    server: SocketAddr,
    name: &Name,
    rtype: HRecordType,
    opts: RawQueryOptions,
) -> Result<Message> {
    let request = build_query(name, rtype, &opts);
    let bytes = request
        .to_vec()
        .map_err(|e| DnsxError::Other(format!("Failed to encode query: {}", e)))?;

    let response = udp_exchange(server, &bytes, request.id(), opts.timeout).await?;
    if response.truncated() {
        return tcp_exchange(server, &bytes, request.id(), opts.timeout).await;
    }
    Ok(response)
}

async fn udp_exchange(
    server: SocketAddr,
    bytes: &[u8],
    id: u16,
    wait: Duration,
) -> Result<Message> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| DnsxError::Other(format!("Failed to bind UDP socket: {}", e)))?;
    socket
        .connect(server)
        .await
        .map_err(|e| DnsxError::Other(format!("Failed to connect to {}: {}", server, e)))?;
    socket
        .send(bytes)
        .await
        .map_err(|e| DnsxError::Other(format!("Failed to send query to {}: {}", server, e)))?;

    let deadline = tokio::time::Instant::now() + wait;
    let mut buf = vec![0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let len = match timeout(remaining, socket.recv(&mut buf)).await {
            Ok(Ok(len)) => len,
            Ok(Err(e)) => {
                return Err(DnsxError::Other(format!(
                    "UDP receive from {} failed: {}",
                    server, e
                )))
            }
            Err(_) => return Err(DnsxError::Other(format!("Query to {} timed out", server))),
        };
        match Message::from_vec(&buf[..len]) {
            // Ignore stray datagrams with another ID
            Ok(message) if message.id() == id => return Ok(message),
            Ok(_) => continue,
            Err(e) => {
                return Err(DnsxError::Other(format!(
                    "Bad response from {}: {}",
                    server, e
                )))
            }
        }
    }
}

async fn tcp_exchange(
    server: SocketAddr,
    bytes: &[u8],
    id: u16,
    wait: Duration,
) -> Result<Message> {
    let mut stream = match timeout(wait, TcpStream::connect(server)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return Err(DnsxError::Other(format!(
                "TCP connection to {} failed: {}",
                server, e
            )))
        }
        Err(_) => {
            return Err(DnsxError::Other(format!(
                "TCP connection to {} timed out",
                server
            )))
        }
    };

    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(bytes);
    stream
        .write_all(&framed)
        .await
        .map_err(|e| DnsxError::Other(format!("Failed to send TCP query to {}: {}", server, e)))?;

    let read = async {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let mut buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        stream.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    };
    let buf = match timeout(wait, read).await {
        Ok(Ok(buf)) => buf,
        Ok(Err(e)) => {
            return Err(DnsxError::Other(format!(
                "TCP read from {} failed: {}",
                server, e
            )))
        }
        Err(_) => {
            return Err(DnsxError::Other(format!(
                "TCP read from {} timed out",
                server
            )))
        }
    };
    let message = Message::from_vec(&buf)
        .map_err(|e| DnsxError::Other(format!("Bad TCP response from {}: {}", server, e)))?;
    if message.id() != id {
        return Err(DnsxError::Other(format!(
            "Mismatched response ID from {}",
            server
        )));
    }
    Ok(message)
}

/// Resolve "host", "host:port", "ip" or "ip:port" (including "[v6]:port") to
/// socket addresses, using the resolver pool for host names. IPv4 comes first.
pub async fn resolve_server(pool: &ResolverPool, server: &str) -> Result<Vec<SocketAddr>> {
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    if let Ok(ip) = server
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()
    {
        return Ok(vec![SocketAddr::new(ip, 53)]);
    }

    let (host, port) = match server.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse::<u16>().unwrap_or(53)),
        _ => (server, 53),
    };
    let host = host.trim_end_matches('.');

    let mut addrs: Vec<SocketAddr> = pool
        .lookup_ipv4(host)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(ip), port))
        .collect();
    addrs.extend(
        pool.lookup_ipv6(host)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|ip| SocketAddr::new(IpAddr::V6(ip), port)),
    );

    if addrs.is_empty() {
        return Err(DnsxError::Other(format!(
            "Failed to resolve nameserver host: {}",
            host
        )));
    }
    Ok(addrs)
}

/// Authoritative nameserver host names for a zone (NS records), without trailing dots.
pub async fn authoritative_nameservers(pool: &ResolverPool, domain: &str) -> Result<Vec<String>> {
    let (lookup, _) = pool.query(domain, RecordType::Ns).await?;
    let mut servers: Vec<String> = lookup
        .iter()
        .filter_map(|rdata| match rdata {
            RData::NS(ns) => Some(ns.to_string().trim_end_matches('.').to_string()),
            _ => None,
        })
        .collect();
    servers.sort();
    servers.dedup();
    Ok(servers)
}

/// Read the strings of the first TXT record in a message's answer section
pub fn first_txt(message: &Message) -> Option<String> {
    message
        .answers()
        .iter()
        .find_map(|record| match record.data() {
            Some(RData::TXT(txt)) => Some(
                txt.iter()
                    .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                    .collect::<Vec<_>>()
                    .join(""),
            ),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_edns_query_with_do_bit() {
        let name = fqdn("example.com").unwrap();
        let opts = RawQueryOptions {
            dnssec_ok: true,
            ..Default::default()
        };
        let message = build_query(&name, HRecordType::SOA, &opts);
        let edns = message.extensions().as_ref().expect("EDNS present");
        assert!(edns.dnssec_ok());
        assert!(!message.recursion_desired());
        assert_eq!(message.queries()[0].name().to_string(), "example.com.");
    }

    #[test]
    fn fqdn_appends_root() {
        assert!(fqdn("example.com").unwrap().is_fqdn());
    }
}
