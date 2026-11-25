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
    /// Server failure
    ServFailOther,
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
            _ => Self::ServFailOther,
        }
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
            ResponseCode::ServFailOther => write!(f, "SERVFAIL"),
        }
    }
}
