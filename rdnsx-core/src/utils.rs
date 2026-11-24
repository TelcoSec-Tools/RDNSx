//! Utility functions for parsing and validation

use std::net::SocketAddr;

use crate::error::{DnsxError, Result};

/// Parse a resolver string into a SocketAddr
pub fn parse_resolver(resolver: &str) -> Result<SocketAddr> {
    let resolver = resolver.trim();
    // "1.2.3.4:53" or "[2001:db8::1]:53"
    if let Ok(addr) = resolver.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // Bare address (IPv4, IPv6, or bracketed IPv6) defaults to port 53
    resolver
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<std::net::IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .map_err(|e| {
            DnsxError::ResolverConfig(format!("Invalid resolver address {}: {}", resolver, e))
        })
}

/// Parse a resolver string into a SocketAddr (legacy function - renamed)
pub fn parse_resolver_string(resolver: &str) -> Result<SocketAddr> {
    parse_resolver(resolver)
}

/// Parse an ASN specification (AS123 or 123)
pub fn parse_asn(asn_spec: &str) -> Result<u32> {
    let asn_str = asn_spec.trim().to_uppercase();
    let asn_str = asn_str.strip_prefix("AS").unwrap_or(&asn_str);

    asn_str
        .parse()
        .map_err(|_| DnsxError::InvalidInput(format!("Invalid ASN: {}", asn_spec)))
}

/// Parse an IP range specification (CIDR notation)
pub fn parse_ip_range(range_spec: &str) -> Result<ipnetwork::IpNetwork> {
    range_spec
        .parse()
        .map_err(|_| DnsxError::InvalidInput(format!("Invalid IP range: {}", range_spec)))
}

/// Reverse IP address for PTR queries
pub fn reverse_ip(ip: &str) -> Result<String> {
    use std::net::IpAddr;

    match ip.parse::<IpAddr>()? {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            Ok(format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            ))
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let mut reversed = String::new();

            for segment in segments.iter().rev() {
                let hex = format!("{:04x}", segment);
                for ch in hex.chars().rev() {
                    reversed.push(ch);
                    reversed.push('.');
                }
            }
            reversed.push_str("ip6.arpa");
            Ok(reversed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resolver_with_port() {
        let result = parse_resolver("8.8.8.8:53");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "8.8.8.8:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_parse_resolver_without_port() {
        let result = parse_resolver("8.8.8.8");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "8.8.8.8:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_parse_resolver_invalid() {
        let result = parse_resolver("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_asn_with_prefix() {
        let result = parse_asn("AS123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 123);
    }

    #[test]
    fn test_parse_asn_without_prefix() {
        let result = parse_asn("123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 123);
    }

    #[test]
    fn test_parse_asn_invalid() {
        let result = parse_asn("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ip_range_ipv4() {
        let result = parse_ip_range("192.168.1.0/24");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "192.168.1.0/24");
    }

    #[test]
    fn test_parse_ip_range_ipv6() {
        let result = parse_ip_range("2001:db8::/32");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_parse_ip_range_invalid() {
        let result = parse_ip_range("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_reverse_ip_ipv4() {
        let result = reverse_ip("192.168.1.1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "1.1.168.192.in-addr.arpa");
    }

    #[test]
    fn test_reverse_ip_ipv6() {
        let result = reverse_ip("2001:db8::1");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn test_reverse_ip_invalid() {
        let result = reverse_ip("invalid");
        assert!(result.is_err());
    }
}
#[cfg(test)]
mod resolver_parse_tests {
    use super::parse_resolver;

    #[test]
    fn parses_resolver_forms() {
        assert_eq!(parse_resolver("8.8.8.8").unwrap().to_string(), "8.8.8.8:53");
        assert_eq!(parse_resolver("8.8.8.8:5353").unwrap().port(), 5353);
        assert_eq!(parse_resolver("2001:4860:4860::8888").unwrap().port(), 53);
        assert_eq!(
            parse_resolver("[2001:4860:4860::8888]:853").unwrap().port(),
            853
        );
        assert!(parse_resolver("not-an-ip").is_err());
    }
}
