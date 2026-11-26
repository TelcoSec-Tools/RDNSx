//! DNS response codes and utilities

use serde::{Deserialize, Serialize};

/// DNS response code
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ResponseCode {
    /// No error condition
    NoError,
    /// Name server failure
    ServFail,
    /// Name does not exist
    NxDomain,
    /// Query refused
    Refused,
    /// Format error
    FormErr,
    /// Not implemented
    NotImp,
    /// Name exists when it should not (RFC 2136)
    YxDomain,
    /// RR set exists when it should not (RFC 2136)
    YxRrset,
    /// RR set that should exist does not (RFC 2136)
    NxRrset,
    /// Server not authoritative for the zone, or not authorized (RFC 2136, RFC 8945)
    NotAuth,
    /// Name not contained in zone (RFC 2136)
    NotZone,
    /// Any other code (extended RCODEs such as BADVERS or BADCOOKIE)
    Other(u16),
}

impl ResponseCode {
    /// Convert from hickory-dns ResponseCode
    pub fn from_hickory(code: hickory_resolver::proto::op::ResponseCode) -> Self {
        use hickory_resolver::proto::op::ResponseCode as HResponseCode;
        match code {
            HResponseCode::NoError => Self::NoError,
            HResponseCode::ServFail => Self::ServFail,
            HResponseCode::NXDomain => Self::NxDomain,
            HResponseCode::Refused => Self::Refused,
            HResponseCode::FormErr => Self::FormErr,
            HResponseCode::NotImp => Self::NotImp,
            HResponseCode::YXDomain => Self::YxDomain,
            HResponseCode::YXRRSet => Self::YxRrset,
            HResponseCode::NXRRSet => Self::NxRrset,
            HResponseCode::NotAuth => Self::NotAuth,
            HResponseCode::NotZone => Self::NotZone,
            other => Self::Other(u16::from(other)),
        }
    }

    /// Parse a response code name (case-insensitive), e.g. "NXDOMAIN"
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name.trim().to_ascii_uppercase().as_str() {
            "NOERROR" => Self::NoError,
            "SERVFAIL" => Self::ServFail,
            "NXDOMAIN" => Self::NxDomain,
            "REFUSED" => Self::Refused,
            "FORMERR" => Self::FormErr,
            "NOTIMP" => Self::NotImp,
            "YXDOMAIN" => Self::YxDomain,
            "YXRRSET" => Self::YxRrset,
            "NXRRSET" => Self::NxRrset,
            "NOTAUTH" => Self::NotAuth,
            "NOTZONE" => Self::NotZone,
            _ => return None,
        })
    }
}

impl std::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseCode::NoError => write!(f, "NOERROR"),
            ResponseCode::ServFail => write!(f, "SERVFAIL"),
            ResponseCode::NxDomain => write!(f, "NXDOMAIN"),
            ResponseCode::Refused => write!(f, "REFUSED"),
            ResponseCode::FormErr => write!(f, "FORMERR"),
            ResponseCode::NotImp => write!(f, "NOTIMP"),
            ResponseCode::YxDomain => write!(f, "YXDOMAIN"),
            ResponseCode::YxRrset => write!(f, "YXRRSET"),
            ResponseCode::NxRrset => write!(f, "NXRRSET"),
            ResponseCode::NotAuth => write!(f, "NOTAUTH"),
            ResponseCode::NotZone => write!(f, "NOTZONE"),
            ResponseCode::Other(code) => write!(f, "RCODE{}", code),
        }
    }
}
