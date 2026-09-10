//! Input handling for domains, IP ranges, and wordlists

use std::io::{self, BufRead};
use std::fs::File;
use std::path::Path;

use crate::error::{DnsxError, Result};

/// Input source for domains
pub enum InputSource {
    /// Stdin
    Stdin,
    /// File path
    File(String),
    /// Command line arguments
    Args(Vec<String>),
}

/// Parse input domains from various sources
pub fn read_domains(source: InputSource) -> Result<Vec<String>> {
    match source {
        InputSource::Stdin => {
            let stdin = io::stdin();
            let lines: Vec<String> = stdin
                .lock()
                .lines()
                .collect::<io::Result<Vec<String>>>()
                .map_err(|e| DnsxError::Other(format!("Failed to read from stdin: {}", e)))?;
            Ok(lines.into_iter().filter(|s| !s.trim().is_empty()).collect())
        }
        InputSource::File(path) => {
            let file = File::open(&path)
                .map_err(|e| DnsxError::Other(format!("Failed to open file {}: {}", path, e)))?;
            let lines: Vec<String> = io::BufReader::new(file)
                .lines()
                .collect::<io::Result<Vec<String>>>()
                .map_err(|e| DnsxError::Other(format!("Failed to read file {}: {}", path, e)))?;
            Ok(lines.into_iter().filter(|s| !s.trim().is_empty()).collect())
        }
        InputSource::Args(domains) => {
            Ok(domains.into_iter().filter(|s| !s.trim().is_empty()).collect())
        }
    }
}

/// Read wordlist from file or stdin
pub fn read_wordlist(source: &str) -> Result<Vec<String>> {
    if source == "-" {
        // Read from stdin
        let stdin = io::stdin();
        let lines: Vec<String> = stdin
            .lock()
            .lines()
            .collect::<io::Result<Vec<String>>>()
            .map_err(|e| DnsxError::Other(format!("Failed to read wordlist from stdin: {}", e)))?;
        Ok(lines.into_iter().filter(|s| !s.trim().is_empty()).collect())
    } else if Path::new(source).exists() {
        // Read from file
        let file = File::open(source)
            .map_err(|e| DnsxError::Other(format!("Failed to open wordlist file {}: {}", source, e)))?;
        let lines: Vec<String> = io::BufReader::new(file)
            .lines()
            .collect::<io::Result<Vec<String>>>()
            .map_err(|e| DnsxError::Other(format!("Failed to read wordlist file {}: {}", source, e)))?;
        Ok(lines.into_iter().filter(|s| !s.trim().is_empty()).collect())
    } else if source.contains(',') {
        // Comma-separated words
        Ok(source.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
    } else {
        // Single word
        Ok(vec![source.to_string()])
    }
}

/// Parse IP network range (CIDR) into individual IPs with a maximum count limit
pub fn parse_ip_range_limited(range: &str, max_ips: usize) -> Result<Vec<std::net::IpAddr>> {
    use ipnetwork::IpNetwork;

    let network: IpNetwork = range
        .parse()
        .map_err(|e| DnsxError::invalid_input(format!("Invalid IP range {}: {}", range, e)))?;

    let ips: Vec<std::net::IpAddr> = network.iter().take(max_ips).collect();
    Ok(ips)
}

/// Parse IP network range (CIDR) into individual IPs (capped at 65536 to prevent OOM)
pub fn parse_ip_range(range: &str) -> Result<Vec<std::net::IpAddr>> {
    parse_ip_range_limited(range, 65536)
}

/// Parse ASN format (AS12345)
pub fn parse_asn(asn_str: &str) -> Result<u32> {
    let asn_str = asn_str.trim();
    if asn_str.to_uppercase().starts_with("AS") {
        let num_str = &asn_str[2..];
        num_str
            .parse::<u32>()
            .map_err(|e| DnsxError::invalid_input(format!("Invalid ASN {}: {}", asn_str, e)))
    } else {
        asn_str
            .parse::<u32>()
            .map_err(|e| DnsxError::invalid_input(format!("Invalid ASN {}: {}", asn_str, e)))
    }
}

/// Reverse DNS lookup for an IP address (PTR record)
pub fn reverse_ip(ip: &std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0])
        }
        std::net::IpAddr::V6(ipv6) => {
            // Convert IPv6 to reverse DNS format
            let segments = ipv6.octets();
            let mut result = String::new();
            for &byte in segments.iter().rev() {
                result.push_str(&format!("{:x}.{:x}.", byte & 0xf, (byte >> 4) & 0xf));
            }
            result.push_str("ip6.arpa");
            result
        }
    }
}
