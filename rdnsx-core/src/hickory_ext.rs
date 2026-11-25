//! Small helpers over the hickory 0.26 API

use hickory_resolver::lookup::Lookup;
use hickory_resolver::proto::rr::rdata::TXT;
use hickory_resolver::proto::rr::RData;

/// Iterate the record data of a lookup's answers (the pre-0.25 `Lookup::iter`)
pub trait LookupExt {
    /// Answer record data, in order
    fn iter(&self) -> impl Iterator<Item = &RData>;
}

impl LookupExt for Lookup {
    fn iter(&self) -> impl Iterator<Item = &RData> {
        self.answers().iter().map(|record| &record.data)
    }
}

/// Iterate the character-strings of a TXT record (the pre-0.25 `TXT::iter`)
pub trait TxtExt {
    /// Character-strings as raw bytes
    fn iter(&self) -> impl Iterator<Item = &[u8]>;
}

impl TxtExt for TXT {
    fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.txt_data.iter().map(|s| s.as_ref())
    }
}
