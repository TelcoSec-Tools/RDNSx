//! A small in-process authoritative DNS server for deterministic tests.
//!
//! It serves one static zone over UDP and TCP on 127.0.0.1, answers AXFR,
//! CHAOS `version.bind`, wildcards under a configured name, and can be told to
//! return SERVFAIL for chosen names.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use hickory_resolver::proto::dnssec::rdata::{DNSSECRData, NSEC};
use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::rdata::{A, CNAME, NS, SOA, TXT};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

pub fn name(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

/// Static zone contents and behaviour switches
#[derive(Clone, Default)]
pub struct MockZone {
    pub origin: Option<Name>,
    pub records: Vec<Record>,
    /// Names below this one resolve (A) to `wildcard_ip` unless defined
    pub wildcard: Option<(Name, std::net::Ipv4Addr)>,
    /// Names below this one are CNAMEs to the target (unless defined)
    pub wildcard_cname: Option<(Name, Name)>,
    /// Names answered with SERVFAIL
    pub servfail: Vec<Name>,
    /// Allow AXFR
    pub allow_axfr: bool,
    /// Delegated child zones: names at or below them get a referral
    pub delegations: Vec<Name>,
    /// Stop the AXFR stream after the first message (no closing SOA)
    pub truncate_axfr: bool,
}

impl MockZone {
    pub fn new(origin: &str) -> Self {
        let origin_name = name(origin);
        let soa = Record::from_rdata(
            origin_name.clone(),
            3600,
            RData::SOA(SOA::new(
                name(&format!("ns1.{}", origin)),
                name(&format!("hostmaster.{}", origin)),
                2024010101,
                7200,
                3600,
                1209600,
                300,
            )),
        );
        let ns = Record::from_rdata(
            origin_name.clone(),
            3600,
            RData::NS(NS(name(&format!("ns1.{}", origin)))),
        );
        Self {
            origin: Some(origin_name),
            records: vec![soa, ns],
            ..Default::default()
        }
    }

    pub fn a(mut self, owner: &str, ip: [u8; 4]) -> Self {
        self.records.push(Record::from_rdata(
            name(owner),
            300,
            RData::A(A::new(ip[0], ip[1], ip[2], ip[3])),
        ));
        self
    }

    pub fn cname(mut self, owner: &str, target: &str) -> Self {
        self.records.push(Record::from_rdata(
            name(owner),
            300,
            RData::CNAME(CNAME(name(target))),
        ));
        self
    }

    pub fn txt(mut self, owner: &str, text: &str) -> Self {
        self.records.push(Record::from_rdata(
            name(owner),
            300,
            RData::TXT(TXT::try_new(std::iter::once(text.as_bytes().to_vec())).unwrap()),
        ));
        self
    }

    pub fn nsec(self, owner: &str, next: &str, types: Vec<RecordType>) -> Self {
        self.nsec_to(owner, name(next), types)
    }

    pub fn nsec_to(mut self, owner: &str, next: Name, types: Vec<RecordType>) -> Self {
        self.records.push(Record::from_rdata(
            name(owner),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, types))),
        ));
        self
    }

    /// Delegate `child` to `ns` (adds the NS record in the parent)
    pub fn delegate(mut self, child: &str, ns: &str) -> Self {
        self.records.push(Record::from_rdata(
            name(child),
            3600,
            RData::NS(NS(name(ns))),
        ));
        self.delegations.push(name(child));
        self
    }

    /// The delegation covering `qname`, unless the query is for DS at the cut
    fn delegation_for(&self, qname: &Name, qtype: RecordType) -> Option<&Name> {
        self.delegations
            .iter()
            .find(|cut| cut.zone_of(qname) && !(*cut == qname && qtype == RecordType::DS))
    }

    /// NSEC records proving that `qname` does not exist (owner < qname < next)
    fn covering_nsec(&self, qname: &Name) -> Vec<Record> {
        let origin = self.origin.clone();
        self.records
            .iter()
            .filter(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::NSEC(nsec)) => {
                    let next = nsec.next_domain_name();
                    let wraps = Some(next) == origin.as_ref();
                    r.name < *qname && (wraps || qname < next)
                }
                _ => false,
            })
            .cloned()
            .collect()
    }

    fn soa(&self) -> Option<Record> {
        self.records
            .iter()
            .find(|r| r.record_type() == RecordType::SOA)
            .cloned()
    }

    fn lookup(&self, qname: &Name, qtype: RecordType) -> (ResponseCode, Vec<Record>) {
        if self.servfail.iter().any(|n| n == qname) {
            return (ResponseCode::ServFail, Vec::new());
        }

        let exact: Vec<Record> = self
            .records
            .iter()
            .filter(|r| &r.name == qname && r.record_type() == qtype)
            .cloned()
            .collect();
        if !exact.is_empty() {
            return (ResponseCode::NoError, exact);
        }

        // Follow a CNAME inside the zone
        if let Some(cname) = self
            .records
            .iter()
            .find(|r| &r.name == qname && r.record_type() == RecordType::CNAME)
        {
            let mut answers = vec![cname.clone()];
            if let RData::CNAME(target) = &cname.data {
                let (_, mut rest) = self.lookup(&target.0, qtype);
                answers.append(&mut rest);
            }
            return (ResponseCode::NoError, answers);
        }

        if self.records.iter().any(|r| &r.name == qname) {
            return (ResponseCode::NoError, Vec::new()); // NODATA
        }

        if let Some((base, target)) = &self.wildcard_cname {
            if base.zone_of(qname) && base != qname {
                let mut answers = vec![Record::from_rdata(
                    qname.clone(),
                    60,
                    RData::CNAME(CNAME(target.clone())),
                )];
                if qtype != RecordType::CNAME {
                    let (_, mut rest) = self.lookup(target, qtype);
                    answers.append(&mut rest);
                }
                return (ResponseCode::NoError, answers);
            }
        }

        if let Some((base, ip)) = &self.wildcard {
            if base.zone_of(qname) && base != qname && qtype == RecordType::A {
                let o = ip.octets();
                return (
                    ResponseCode::NoError,
                    vec![Record::from_rdata(
                        qname.clone(),
                        60,
                        RData::A(A::new(o[0], o[1], o[2], o[3])),
                    )],
                );
            }
        }

        (ResponseCode::NXDomain, Vec::new())
    }

    fn respond(&self, request: &Message) -> Vec<Message> {
        let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
        response.metadata.authoritative = true;
        response.metadata.recursion_desired = request.recursion_desired;
        response.metadata.recursion_available = false;
        if request.edns.is_some() {
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            response.set_edns(edns);
        }

        let Some(query) = request.queries.first().cloned() else {
            response.metadata.response_code = ResponseCode::FormErr;
            return vec![response];
        };
        response.add_query(query.clone());

        if query.query_class() == DNSClass::CH {
            if query.name() == &name("version.bind.") && query.query_type() == RecordType::TXT {
                let mut rec = Record::from_rdata(
                    query.name().clone(),
                    0,
                    RData::TXT(TXT::try_new(std::iter::once(b"mock-dns 1.0".to_vec())).unwrap()),
                );
                rec.dns_class = DNSClass::CH;
                response.add_answer(rec);
            } else {
                response.metadata.response_code = ResponseCode::Refused;
            }
            return vec![response];
        }

        if query.query_type() == RecordType::AXFR {
            if !self.allow_axfr {
                response.metadata.response_code = ResponseCode::Refused;
                return vec![response];
            }
            let soa = self.soa().expect("zone has SOA");
            let body: Vec<Record> = self
                .records
                .iter()
                .filter(|r| r.record_type() != RecordType::SOA)
                .cloned()
                .collect();
            // Split across two messages, as real servers do for large zones
            let mut first = response.clone();
            first.add_answer(soa.clone());
            let half = body.len() / 2;
            for r in &body[..half] {
                first.add_answer(r.clone());
            }
            let mut second = response;
            for r in &body[half..] {
                second.add_answer(r.clone());
            }
            second.add_answer(soa);
            if self.truncate_axfr {
                return vec![first];
            }
            return vec![first, second];
        }

        if let Some(cut) = self.delegation_for(query.name(), query.query_type()) {
            // Referral: no answer, NS (and NSEC for the unsigned cut) in authority
            response.metadata.authoritative = false;
            for r in self.records.iter().filter(|r| {
                &r.name == cut && r.record_type() == RecordType::NS
            }) {
                response.add_authority(r.clone());
            }
            return vec![response];
        }

        let (rcode, answers) = self.lookup(query.name(), query.query_type());
        response.metadata.response_code = rcode;
        for answer in answers {
            response.add_answer(answer);
        }
        if response.answers.is_empty() {
            if let Some(soa) = self.soa() {
                response.add_authority(soa);
            }
            if rcode == ResponseCode::NXDomain {
                for nsec in self.covering_nsec(query.name()) {
                    response.add_authority(nsec);
                }
            }
        }
        vec![response]
    }
}

/// Start the server; returns the address it listens on (UDP and TCP)
pub async fn spawn(zone: MockZone) -> SocketAddr {
    let zone = Arc::new(zone);

    // Find a port free for both UDP and TCP
    let (udp, tcp) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        if let Ok(tcp) = TcpListener::bind(addr).await {
            break (udp, tcp);
        }
    };
    let addr = udp.local_addr().unwrap();

    let udp_zone = Arc::clone(&zone);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = udp.recv_from(&mut buf).await else {
                continue;
            };
            let Ok(request) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            for response in udp_zone.respond(&request) {
                let _ = udp.send_to(&response.to_vec().unwrap(), peer).await;
            }
        }
    });

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else {
                continue;
            };
            let zone = Arc::clone(&zone);
            tokio::spawn(async move {
                loop {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let mut buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
                    if stream.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let Ok(request) = Message::from_vec(&buf) else {
                        return;
                    };
                    for response in zone.respond(&request) {
                        let bytes = response.to_vec().unwrap();
                        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&bytes);
                        if stream.write_all(&framed).await.is_err() {
                            return;
                        }
                    }
                    let is_axfr = request
                        .queries
                        .first()
                        .is_some_and(|q| q.query_type() == RecordType::AXFR);
                    if zone.truncate_axfr && is_axfr {
                        return; // drop the connection mid-transfer
                    }
                }
            });
        }
    });

    addr
}
