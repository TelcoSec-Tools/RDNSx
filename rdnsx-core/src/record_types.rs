//! DNS record types enumeration and conversion utilities

use serde::{Deserialize, Serialize};

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    /// A record (IPv4 address)
    A,
    /// AAAA record (IPv6 address)
    Aaaa,
    /// CNAME record (canonical name)
    Cname,
    /// MX record (mail exchange)
    Mx,
    /// TXT record (text)
    Txt,
    /// NS record (name server)
    Ns,
    /// SOA record (start of authority)
    Soa,
    /// PTR record (pointer/reverse DNS)
    Ptr,
    /// SRV record (service)
    Srv,
    /// AFSDB record
    Afsdb,
    /// CAA record (Certification Authority Authorization)
    Caa,
    /// CERT record (certificate)
    Cert,
    /// DNAME record (delegation name)
    Dname,
    /// DNSKEY record (DNSSEC key)
    Dnskey,
    /// DS record (delegation signer)
    Ds,
    /// HINFO record (host information)
    Hinfo,
    /// HTTPS record
    Https,
    /// KEY record
    Key,
    /// LOC record (location)
    Loc,
    /// NAPTR record (naming authority pointer)
    Naptr,
    /// NSEC record (DNSSEC)
    Nsec,
    /// NSEC3 record (DNSSEC)
    Nsec3,
    /// OPT record (EDNS options)
    Opt,
    /// RRSIG record (DNSSEC signature)
    Rrsig,
    /// SSHFP record (SSH fingerprint)
    Sshfp,
    /// SVCB record (service binding)
    Svcb,
    /// TLSA record (TLSA certificate association)
    Tlsa,
    /// URI record (uniform resource identifier)
    Uri,
}

impl RecordType {
    /// Get all supported record types
    pub fn all() -> Vec<RecordType> {
        vec![
            RecordType::A,
            RecordType::Aaaa,
            RecordType::Cname,
            RecordType::Mx,
            RecordType::Txt,
            RecordType::Ns,
            RecordType::Soa,
            RecordType::Ptr,
            RecordType::Srv,
            RecordType::Afsdb,
            RecordType::Caa,
            RecordType::Cert,
            RecordType::Dname,
            RecordType::Dnskey,
            RecordType::Ds,
            RecordType::Hinfo,
            RecordType::Https,
            RecordType::Key,
            RecordType::Loc,
            RecordType::Naptr,
            RecordType::Nsec,
            RecordType::Nsec3,
            RecordType::Opt,
            RecordType::Rrsig,
            RecordType::Sshfp,
            RecordType::Svcb,
            RecordType::Tlsa,
            RecordType::Uri,
        ]
    }

    /// Convert to hickory-dns RecordType
    pub fn to_hickory(&self) -> hickory_resolver::proto::rr::RecordType {
        use hickory_resolver::proto::rr::RecordType as HRecordType;
        match self {
            RecordType::A => HRecordType::A,
            RecordType::Aaaa => HRecordType::AAAA,
            RecordType::Cname => HRecordType::CNAME,
            RecordType::Mx => HRecordType::MX,
            RecordType::Txt => HRecordType::TXT,
            RecordType::Ns => HRecordType::NS,
            RecordType::Soa => HRecordType::SOA,
            RecordType::Ptr => HRecordType::PTR,
            RecordType::Srv => HRecordType::SRV,
            // RecordType::Afsdb => HRecordType::AFSDB,
            RecordType::Caa => HRecordType::CAA,
            // RecordType::Cert => HRecordType::CERT,
            RecordType::Dname => HRecordType::Unknown(39),
            RecordType::Dnskey => HRecordType::DNSKEY,
            RecordType::Ds => HRecordType::DS,
            RecordType::Hinfo => HRecordType::HINFO,
            RecordType::Https => HRecordType::HTTPS,
            RecordType::Key => HRecordType::KEY,
            RecordType::Loc => HRecordType::Unknown(29),
            RecordType::Naptr => HRecordType::NAPTR,
            RecordType::Nsec => HRecordType::NSEC,
            RecordType::Nsec3 => HRecordType::NSEC3,
            RecordType::Opt => HRecordType::OPT,
            RecordType::Rrsig => HRecordType::RRSIG,
            RecordType::Sshfp => HRecordType::SSHFP,
            RecordType::Svcb => HRecordType::SVCB,
            RecordType::Tlsa => HRecordType::TLSA,
            RecordType::Afsdb => HRecordType::Unknown(18),
            RecordType::Cert => HRecordType::Unknown(37),
            RecordType::Uri => HRecordType::Unknown(256),
        }
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::Aaaa => write!(f, "AAAA"),
            RecordType::Cname => write!(f, "CNAME"),
            RecordType::Mx => write!(f, "MX"),
            RecordType::Txt => write!(f, "TXT"),
            RecordType::Ns => write!(f, "NS"),
            RecordType::Soa => write!(f, "SOA"),
            RecordType::Ptr => write!(f, "PTR"),
            RecordType::Srv => write!(f, "SRV"),
            RecordType::Afsdb => write!(f, "AFSDB"),
            RecordType::Caa => write!(f, "CAA"),
            RecordType::Cert => write!(f, "CERT"),
            RecordType::Dname => write!(f, "DNAME"),
            RecordType::Dnskey => write!(f, "DNSKEY"),
            RecordType::Ds => write!(f, "DS"),
            RecordType::Hinfo => write!(f, "HINFO"),
            RecordType::Https => write!(f, "HTTPS"),
            RecordType::Key => write!(f, "KEY"),
            RecordType::Loc => write!(f, "LOC"),
            RecordType::Naptr => write!(f, "NAPTR"),
            RecordType::Nsec => write!(f, "NSEC"),
            RecordType::Nsec3 => write!(f, "NSEC3"),
            RecordType::Opt => write!(f, "OPT"),
            RecordType::Rrsig => write!(f, "RRSIG"),
            RecordType::Sshfp => write!(f, "SSHFP"),
            RecordType::Svcb => write!(f, "SVCB"),
            RecordType::Tlsa => write!(f, "TLSA"),
            RecordType::Uri => write!(f, "URI"),
        }
    }
}