//! IP-to-ASN mapping over DNS (Team Cymru IP to ASN service)
//!
//! `<reversed-ip>.origin.asn.cymru.com TXT` returns
//! `"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"`, and
//! `AS13335.asn.cymru.com TXT` returns
//! `"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"`.

use std::net::IpAddr;

use hickory_resolver::proto::rr::RData;
use serde::{Deserialize, Serialize};

use crate::error::{DnsxError, Result};
use crate::resolver::ResolverPool;
use crate::types::RecordType;

/// Origin AS information for an IP address
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpAsnRecord {
    pub asn: u32,
    pub prefix: String,
    pub country: Option<String>,
    pub registry: Option<String>,
    pub as_name: Option<String>,
}

/// Name to query for the origin of `ip`
pub fn origin_query_name(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<String> = v6
                .octets()
                .iter()
                .flat_map(|b| [b >> 4, b & 0x0f])
                .rev()
                .map(|n| format!("{:x}", n))
                .collect();
            format!("{}.origin6.asn.cymru.com", nibbles.join("."))
        }
    }
}

fn fields(txt: &str) -> Vec<String> {
    txt.split('|').map(|f| f.trim().to_string()).collect()
}

/// Parse an origin TXT answer. Multi-origin prefixes list several ASNs: the first is used.
pub fn parse_origin_txt(txt: &str) -> Option<IpAsnRecord> {
    let f = fields(txt);
    let asn = f.first()?.split_whitespace().next()?.parse().ok()?;
    let non_empty = |i: usize| f.get(i).filter(|s| !s.is_empty()).cloned();
    Some(IpAsnRecord {
        asn,
        prefix: f.get(1).cloned().unwrap_or_default(),
        country: non_empty(2),
        registry: non_empty(3),
        as_name: None,
    })
}

/// Parse an AS description TXT answer, returning the AS name
pub fn parse_as_name_txt(txt: &str) -> Option<String> {
    fields(txt).get(4).filter(|s| !s.is_empty()).cloned()
}

async fn first_txt(pool: &ResolverPool, name: &str) -> Result<Option<String>> {
    let (lookup, _) = pool.query(name, RecordType::Txt).await?;
    Ok(lookup.iter().find_map(|rdata| match rdata {
        RData::TXT(txt) => Some(
            txt.iter()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .collect::<String>(),
        ),
        _ => None,
    }))
}

/// Look up the origin AS (and its name) for an IP address
pub async fn lookup_ip_asn(pool: &ResolverPool, ip: &IpAddr) -> Result<IpAsnRecord> {
    let txt = first_txt(pool, &origin_query_name(ip))
        .await?
        .ok_or_else(|| DnsxError::Other(format!("No ASN data for {}", ip)))?;
    let mut record = parse_origin_txt(&txt)
        .ok_or_else(|| DnsxError::Other(format!("Unparseable ASN data: {}", txt)))?;
    if let Ok(Some(desc)) = first_txt(pool, &format!("AS{}.asn.cymru.com", record.asn)).await {
        record.as_name = parse_as_name_txt(&desc);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_query_names() {
        assert_eq!(
            origin_query_name(&"1.2.3.4".parse().unwrap()),
            "4.3.2.1.origin.asn.cymru.com"
        );
        let v6 = origin_query_name(&"2001:db8::1".parse().unwrap());
        assert!(v6.starts_with("1.0.0.0."));
        assert!(v6.ends_with("8.b.d.0.1.0.0.2.origin6.asn.cymru.com"));
    }

    #[test]
    fn parses_answers() {
        let r = parse_origin_txt("13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11").unwrap();
        assert_eq!(r.asn, 13335);
        assert_eq!(r.prefix, "1.1.1.0/24");
        assert_eq!(r.country.as_deref(), Some("AU"));
        assert_eq!(
            parse_as_name_txt("13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US").as_deref(),
            Some("CLOUDFLARENET, US")
        );
    }
}
