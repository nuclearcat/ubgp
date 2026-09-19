//! Small bounded BGP codec. No received route is installed or re-exported.
use crate::config::{Config, Peer, valid_router_id, valid_v4};
use anyhow::{Result, ensure};
use ipnet::IpNet;
use std::{fmt, net::Ipv4Addr};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const MAX_MESSAGE: usize = 4096;
// Keep even a full IPv6 batch with both next hops within MAX_MESSAGE.
pub(crate) const MAX_UPDATE_PREFIXES: usize = 200;
pub const KEEPALIVE: u8 = 4;
pub const UPDATE: u8 = 2;
pub const ROUTE_REFRESH: u8 = 5;
#[derive(Debug)]
pub struct ProtocolError {
    pub code: u8,
    pub subcode: u8,
    pub data: Vec<u8>,
    pub reason: &'static str,
}
impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BGP {}.{}: {}", self.code, self.subcode, self.reason)
    }
}
impl std::error::Error for ProtocolError {}
fn err(code: u8, subcode: u8, reason: &'static str) -> anyhow::Error {
    ProtocolError {
        code,
        subcode,
        data: vec![],
        reason,
    }
    .into()
}
fn require(ok: bool, code: u8, subcode: u8, reason: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(err(code, subcode, reason))
    }
}
fn u16b(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Wrap a body in a BGP header with the standard marker and supplied message type.
///
/// # Panics
/// Panics if the complete message exceeds [`MAX_MESSAGE`].
pub fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() + 19 <= MAX_MESSAGE);
    let mut out = vec![255u8; 16];
    out.extend_from_slice(&((body.len() + 19) as u16).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}
/// Encode a NOTIFICATION, truncating error data to fit the standard message limit.
pub fn notification(code: u8, subcode: u8, data: &[u8]) -> Vec<u8> {
    let mut b = vec![code, subcode];
    b.extend_from_slice(&data[..data.len().min(MAX_MESSAGE - 21)]);
    frame(3, &b)
}
/// Read one frame, validating its marker, type, and length before allocating the body.
/// Returns the type and body without the header; callers must impose any deadline.
/// Cancellation may consume a partial frame, so do not resume on the same stream.
pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 19];
    reader.read_exact(&mut header).await?;
    require(header[..16] == [255u8; 16], 1, 1, "invalid marker")?;
    let len = u16b(&header[16..18]) as usize;
    if !(19..=MAX_MESSAGE).contains(&len) {
        return Err(ProtocolError {
            code: 1,
            subcode: 2,
            data: header[16..18].to_vec(),
            reason: "invalid message length",
        }
        .into());
    }
    let kind = header[18];
    if !(1..=5).contains(&kind) {
        return Err(ProtocolError {
            code: 1,
            subcode: 3,
            data: vec![kind],
            reason: "invalid message type",
        }
        .into());
    }
    let valid_length = match kind {
        1 => len >= 29,
        2 => len >= 23,
        3 => len >= 21,
        4 => len == 19,
        5 => len == 23,
        _ => false,
    };
    if !valid_length {
        return Err(ProtocolError {
            code: 1,
            subcode: 2,
            data: header[16..18].to_vec(),
            reason: "invalid length for message type",
        }
        .into());
    }
    let mut body = vec![0; len - 19];
    reader.read_exact(&mut body).await?;
    Ok((kind, body))
}

#[derive(Clone, Debug)]
pub struct Negotiated {
    pub router_id: Ipv4Addr,
    pub hold: u16,
    pub asn4: bool,
    pub internal: bool,
    pub ipv4: bool,
    pub ipv6: bool,
}
/// Encode an OPEN advertising four-octet ASNs, route refresh, and enabled families.
pub fn open(cfg: &Config, peer: &Peer) -> Vec<u8> {
    let mut caps = vec![65, 4];
    caps.extend_from_slice(&cfg.asn.to_be_bytes());
    caps.extend_from_slice(&[2, 0]); // Basic Route Refresh (RFC 2918).
    if peer.ipv4 {
        caps.extend_from_slice(&[1, 4, 0, 1, 0, 1]);
    }
    if peer.ipv6 {
        caps.extend_from_slice(&[1, 4, 0, 2, 0, 1]);
    }
    let mut body = vec![4];
    body.extend_from_slice(&(u16::try_from(cfg.asn).unwrap_or(23456)).to_be_bytes());
    body.extend_from_slice(&peer.hold_time_secs.to_be_bytes());
    body.extend_from_slice(&cfg.router_id.octets());
    body.push((caps.len() + 2) as u8);
    body.push(2);
    body.push(caps.len() as u8);
    body.extend(caps);
    frame(1, &body)
}
/// Validate an OPEN body against the expected peer and negotiate hold time and families.
/// Peers without multiprotocol capabilities may use legacy IPv4 unicast.
pub fn parse_open(b: &[u8], cfg: &Config, p: &Peer) -> Result<Negotiated> {
    require(b.len() >= 10, 2, 0, "short OPEN")?;
    if b[0] != 4 {
        return Err(ProtocolError {
            code: 2,
            subcode: 1,
            data: vec![0, 4],
            reason: "unsupported version",
        }
        .into());
    }
    let old_asn = u16b(&b[1..3]) as u32;
    let hold = u16b(&b[3..5]);
    require(hold == 0 || hold >= 3, 2, 6, "unacceptable hold time")?;
    let router_id = Ipv4Addr::new(b[5], b[6], b[7], b[8]);
    require(
        valid_router_id(router_id) && (cfg.asn != p.remote_asn || router_id != cfg.router_id),
        2,
        3,
        "invalid or duplicate router ID",
    )?;
    // RFC 9072: the type-255 discriminator selects both extended length fields.
    // The legacy length byte is ignored once that discriminator is present.
    let extended = b[9] != 0 && b.get(10) == Some(&255);
    let (mut params, parameter_header) = if extended {
        require(b.len() >= 13, 2, 0, "short extended OPEN length")?;
        require(
            u16b(&b[11..13]) as usize + 13 == b.len(),
            2,
            0,
            "invalid extended OPEN parameter length",
        )?;
        (&b[13..], 3)
    } else {
        require(
            b[9] as usize + 10 == b.len(),
            2,
            0,
            "invalid OPEN parameter length",
        )?;
        (&b[10..], 2)
    };
    let mut as4 = None;
    let mut mp = false;
    let mut v4 = false;
    let mut v6 = false;
    while !params.is_empty() {
        require(
            params.len() >= parameter_header,
            2,
            0,
            "short optional parameter header",
        )?;
        let length = if extended {
            u16b(&params[1..3]) as usize
        } else {
            params[1] as usize
        };
        let end = parameter_header + length;
        require(end <= params.len(), 2, 0, "invalid optional parameter")?;
        if params[0] != 2 {
            return Err(ProtocolError {
                code: 2,
                subcode: 4,
                data: params[..end].to_vec(),
                reason: "unsupported optional parameter",
            }
            .into());
        }
        // Capability lengths remain one octet even inside extended parameters.
        let mut caps = &params[parameter_header..end];
        while !caps.is_empty() {
            require(
                caps.len() >= 2 && caps[1] as usize + 2 <= caps.len(),
                2,
                0,
                "invalid capability length",
            )?;
            let data = &caps[2..2 + caps[1] as usize];
            match caps[0] {
                1 => {
                    require(data.len() == 4, 2, 0, "invalid multiprotocol capability")?;
                    mp = true;
                    if data[3] == 1 {
                        v4 |= u16b(data) == 1;
                        v6 |= u16b(data) == 2;
                    }
                }
                2 => require(data.is_empty(), 2, 0, "invalid route refresh capability")?,
                65 => {
                    require(data.len() == 4, 2, 0, "invalid four-octet ASN capability")?;
                    let value = u32::from_be_bytes(data.try_into().unwrap());
                    require(
                        as4.is_none_or(|a| a == value),
                        2,
                        2,
                        "conflicting ASN capabilities",
                    )?;
                    as4 = Some(value);
                }
                _ => {} // Unknown capabilities are ignored per RFC 5492.
            }
            caps = &caps[2 + caps[1] as usize..];
        }
        params = &params[end..];
    }
    require(
        as4.unwrap_or(old_asn) == p.remote_asn,
        2,
        2,
        "unexpected peer ASN",
    )?;
    require(
        old_asn == u16::try_from(p.remote_asn).unwrap_or(23456) as u32,
        2,
        2,
        "inconsistent two-octet peer ASN",
    )?;
    let n = Negotiated {
        router_id,
        hold: hold.min(p.hold_time_secs),
        asn4: as4.is_some(),
        internal: cfg.asn == p.remote_asn,
        ipv4: p.ipv4 && (v4 || !mp),
        ipv6: p.ipv6 && v6,
    };
    if !n.ipv4 && !n.ipv6 {
        let mut data = Vec::new();
        if p.ipv4 {
            data.extend_from_slice(&[1, 4, 0, 1, 0, 1]);
        }
        if p.ipv6 {
            data.extend_from_slice(&[1, 4, 0, 2, 0, 1]);
        }
        return Err(ProtocolError {
            code: 2,
            subcode: 7,
            data,
            reason: "no common address family",
        }
        .into());
    }
    Ok(n)
}

/// Append a path attribute, selecting the extended length field when needed.
fn attr(out: &mut Vec<u8>, flags: u8, kind: u8, data: &[u8]) {
    out.push(flags | if data.len() > 255 { 0x10 } else { 0 });
    out.push(kind);
    if data.len() > 255 {
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    } else {
        out.push(data.len() as u8);
    }
    out.extend_from_slice(data);
}
/// Append a prefix length and the minimum network-address bytes required for NLRI.
fn nlri(out: &mut Vec<u8>, p: &IpNet) {
    out.push(p.prefix_len());
    let n = (p.prefix_len() as usize).div_ceil(8);
    match p {
        IpNet::V4(p) => out.extend_from_slice(&p.network().octets()[..n]),
        IpNet::V6(p) => out.extend_from_slice(&p.network().octets()[..n]),
    }
}
/// Encode one announcement or withdrawal batch using the peer's next hops and ASN width.
/// Announcements require a validated next hop for the batch's address family.
///
/// # Panics
/// Panics for empty, mixed-family, or oversized batches, or a missing required next hop.
/// A batch may contain at most 200 prefixes.
pub fn update(
    cfg: &Config,
    p: &Peer,
    n: &Negotiated,
    prefixes: &[IpNet],
    withdraw: bool,
) -> Vec<u8> {
    assert!(!prefixes.is_empty() && prefixes.len() <= MAX_UPDATE_PREFIXES);
    let v6 = prefixes[0].addr().is_ipv6();
    assert!(prefixes.iter().all(|p| p.addr().is_ipv6() == v6));
    let mut encoded = Vec::new();
    for prefix in prefixes {
        nlri(&mut encoded, prefix);
    }
    let mut attrs = Vec::new();
    // RFC 7606 requires MP NLRI first so it can be located before other attributes.
    if v6 {
        let mut mp = vec![0, 2, 1];
        if !withdraw {
            mp.push(if p.next_hop_v6_link_local.is_some() {
                32
            } else {
                16
            });
            mp.extend_from_slice(&p.nh6().expect("validated next hop").octets());
            if let Some(link_local) = p.next_hop_v6_link_local {
                mp.extend_from_slice(&link_local.octets());
            }
            mp.push(0);
        }
        mp.extend_from_slice(&encoded);
        attr(&mut attrs, 0x80, if withdraw { 15 } else { 14 }, &mp);
    }
    if !withdraw {
        attr(&mut attrs, 0x40, 1, &[2]); // ORIGIN INCOMPLETE: redistributed kernel routes.
        let mut path = Vec::new();
        if cfg.asn != p.remote_asn {
            path.extend_from_slice(&[2, 1]);
            if n.asn4 {
                path.extend_from_slice(&cfg.asn.to_be_bytes());
            } else {
                path.extend_from_slice(&u16::try_from(cfg.asn).unwrap_or(23456).to_be_bytes());
            }
        }
        attr(&mut attrs, 0x40, 2, &path);
        if !n.asn4 && cfg.asn > 65535 && cfg.asn != p.remote_asn {
            let mut as4 = vec![2, 1];
            as4.extend_from_slice(&cfg.asn.to_be_bytes());
            attr(&mut attrs, 0xc0, 17, &as4);
        }
        if cfg.asn == p.remote_asn {
            attr(&mut attrs, 0x40, 5, &100u32.to_be_bytes());
        }
        if !v6 {
            attr(
                &mut attrs,
                0x40,
                3,
                &p.nh4().expect("validated next hop").octets(),
            );
        }
    }
    let mut body = Vec::new();
    if withdraw && !v6 {
        body.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
        body.extend_from_slice(&encoded);
    } else {
        body.extend_from_slice(&[0, 0]);
    }
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend(attrs);
    if !withdraw && !v6 {
        body.extend(encoded);
    }
    frame(UPDATE, &body)
}
/// Encode an empty UPDATE marking end of RIB for IPv6 when `v6`, otherwise IPv4.
pub fn end_of_rib(v6: bool) -> Vec<u8> {
    if v6 {
        frame(UPDATE, &[0, 0, 0, 6, 0x80, 15, 3, 0, 2, 1])
    } else {
        frame(UPDATE, &[0, 0, 0, 0])
    }
}

/// Check packed prefix lengths and available bytes for an address width in bits.
fn validate_nlri(mut b: &[u8], bits: usize) -> Result<()> {
    while !b.is_empty() {
        let n = (b[0] as usize).div_ceil(8);
        require(b[0] as usize <= bits && n < b.len(), 3, 10, "invalid NLRI")?;
        b = &b[n + 1..];
    }
    Ok(())
}
/// Check AS_PATH segment types and lengths using a two- or four-byte ASN width.
fn validate_path(mut b: &[u8], width: usize) -> Result<()> {
    while !b.is_empty() {
        require(
            b.len() >= 2 && (1..=4).contains(&b[0]) && b[1] > 0,
            3,
            11,
            "invalid AS_PATH segment",
        )?;
        let len = 2 + width * b[1] as usize;
        require(len <= b.len(), 3, 11, "truncated AS_PATH")?;
        b = &b[len..];
    }
    Ok(())
}
/// The strongest nonfatal handling required for a received UPDATE.
/// ubgp has no inbound RIB, so both recovery actions preserve the session without
/// installing routes. Fatal errors are returned separately as [`ProtocolError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UpdateAction {
    Valid,
    AttributeDiscard,
    TreatAsWithdraw,
}

/// Check an UPDATE and classify recoverable errors under RFC 7606 and RFC 6793.
/// Continue checking after recoverable errors so a later fatal error still wins.
///
/// # Errors
/// Returns a protocol error when framing or NLRI cannot be recovered safely,
/// MP attributes are duplicated, or an unknown well-known attribute is received.
pub fn validate_update(b: &[u8], n: &Negotiated) -> Result<UpdateAction> {
    use UpdateAction::*;
    require(b.len() >= 4, 3, 1, "short UPDATE")?;
    let w = u16b(b) as usize;
    require(w + 4 <= b.len(), 3, 1, "invalid withdrawn length")?;
    validate_nlri(&b[2..2 + w], 32)?;
    let a = u16b(&b[2 + w..]) as usize;
    require(w + a + 4 <= b.len(), 3, 1, "invalid attributes length")?;
    let tail = &b[4 + w + a..];
    validate_nlri(tail, 32)?;
    let mut attrs = &b[4 + w..4 + w + a];
    let mut seen = [false; 256];
    let mut mp_reach = false;
    let mut action = Valid;
    while !attrs.is_empty() {
        // The enclosing length still locates legacy NLRI if an attribute header
        // or length is broken. Without reachable NLRI, recovery is unsafe.
        if attrs.len() < 3 {
            action = TreatAsWithdraw;
            break;
        }
        let flags = attrs[0];
        let kind = attrs[1] as usize;
        let h = if flags & 0x10 != 0 { 4 } else { 3 };
        let mp = kind == 14 || kind == 15;
        if attrs.len() < h {
            require(!mp, 3, 9, "short multiprotocol attribute header")?;
            action = TreatAsWithdraw;
            break;
        }
        let l = if h == 4 {
            u16b(&attrs[2..]) as usize
        } else {
            attrs[2] as usize
        };
        if h + l > attrs.len() {
            require(!mp, 3, 9, "truncated multiprotocol attribute")?;
            action = TreatAsWithdraw;
            break;
        }
        let data = &attrs[h..h + l];
        if seen[kind] {
            require(!mp, 3, 1, "duplicate multiprotocol attribute")?;
            action = action.max(AttributeDiscard);
            attrs = &attrs[h + l..];
            continue;
        }
        seen[kind] = true;
        // These attributes must be discarded regardless of their value or flags.
        if (n.asn4 && matches!(kind, 17 | 18)) || (!n.internal && matches!(kind, 5 | 9 | 10)) {
            action = action.max(AttributeDiscard);
            attrs = &attrs[h + l..];
            continue;
        }
        let expected = match kind {
            1 | 2 | 3 | 5 | 6 => Some(0x40),
            4 | 9 | 10 | 14 | 15 => Some(0x80),
            7 | 8 | 16 | 17 | 18 | 32 => Some(0xc0),
            _ => None,
        };
        let flags_ok = expected.is_none_or(|expected| {
            flags & 0xc0 == expected && (flags & 0x20 == 0 || expected == 0xc0)
        });
        if mp {
            require(flags_ok, 3, 9, "invalid multiprotocol attribute flags")?;
            require(l >= 3, 3, 9, "short multiprotocol attribute")?;
            let afi = u16b(data);
            let mut start = 3;
            if kind == 14 {
                require(
                    l >= 5 && data[3] as usize + 5 <= l,
                    3,
                    9,
                    "invalid MP_REACH next hop",
                )?;
                if data[2] == 1 && (afi == 1 || afi == 2) {
                    require(
                        if afi == 2 {
                            data[3] == 16 || data[3] == 32
                        } else {
                            data[3] == 4
                        },
                        3,
                        9,
                        "invalid MP_REACH next-hop size",
                    )?;
                }
                start = 5 + data[3] as usize;
            }
            if data[2] == 1 && (afi == 1 || afi == 2) {
                validate_nlri(&data[start..], if afi == 1 { 32 } else { 128 })?;
                mp_reach |= kind == 14 && start < l;
            }
        } else {
            let valid = match kind {
                1 => l == 1 && data[0] <= 2,
                2 => validate_path(data, if n.asn4 { 4 } else { 2 }).is_ok(),
                3 => l == 4 && valid_v4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                4 | 5 | 9 => l == 4,
                6 => l == 0,
                7 => l == if n.asn4 { 8 } else { 6 },
                8 | 10 => l != 0 && l % 4 == 0,
                16 => l != 0 && l % 8 == 0,
                17 => l >= 6 && l % 2 == 0 && validate_path(data, 4).is_ok(),
                18 => l == 8,
                32 => l != 0 && l % 12 == 0,
                _ => {
                    if flags & 0x80 == 0 {
                        return Err(ProtocolError {
                            code: 3,
                            subcode: 2,
                            data: attrs[..h + l].to_vec(),
                            reason: "unknown well-known attribute",
                        }
                        .into());
                    }
                    true
                }
            };
            if !flags_ok || !valid {
                action = action.max(if matches!(kind, 6 | 7 | 17 | 18) {
                    AttributeDiscard
                } else {
                    TreatAsWithdraw
                });
            }
        }
        attrs = &attrs[h + l..];
    }
    let reachable = !tail.is_empty() || mp_reach;
    if reachable && (!seen[1] || !seen[2] || (n.internal && !seen[5])) {
        action = TreatAsWithdraw;
    }
    if !tail.is_empty() && !seen[3] {
        action = TreatAsWithdraw;
    }
    require(
        action != TreatAsWithdraw || reachable,
        3,
        1,
        "cannot recover UPDATE without reachable NLRI",
    )?;
    Ok(action)
}

/// Decode supported reachable NLRI for recovery diagnostics after validation.
/// Stop at malformed attribute boundaries; never interpret unknown address families.
pub(crate) fn update_prefixes(b: &[u8]) -> Vec<IpNet> {
    fn append(mut b: &[u8], v6: bool, out: &mut Vec<IpNet>) {
        while !b.is_empty() {
            let bits = b[0];
            let size = (bits as usize).div_ceil(8);
            if bits as usize > if v6 { 128 } else { 32 } || size + 1 > b.len() {
                break;
            }
            let mut bytes = [0; 16];
            bytes[..size].copy_from_slice(&b[1..1 + size]);
            let ip = if v6 {
                std::net::IpAddr::V6(bytes.into())
            } else {
                std::net::IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            };
            out.push(IpNet::new(ip, bits).unwrap().trunc());
            b = &b[1 + size..];
        }
    }
    let mut out = Vec::new();
    if b.len() < 4 {
        return out;
    }
    let w = u16b(b) as usize;
    if w + 4 > b.len() {
        return out;
    }
    let a = u16b(&b[2 + w..]) as usize;
    if w + a + 4 > b.len() {
        return out;
    }
    append(&b[4 + w + a..], false, &mut out);
    let mut attrs = &b[4 + w..4 + w + a];
    while attrs.len() >= 3 {
        let h = if attrs[0] & 0x10 != 0 { 4 } else { 3 };
        if attrs.len() < h {
            break;
        }
        let l = if h == 4 {
            u16b(&attrs[2..]) as usize
        } else {
            attrs[2] as usize
        };
        if h + l > attrs.len() {
            break;
        }
        let data = &attrs[h..h + l];
        if attrs[1] == 14 && l >= 5 && data[2] == 1 {
            let start = 5 + data[3] as usize;
            let afi = u16b(data);
            if start <= l && (afi == 1 || afi == 2) {
                append(&data[start..], afi == 2, &mut out);
            }
        }
        attrs = &attrs[h + l..];
    }
    out
}
/// Decode a basic unicast refresh: `Some(true)` for IPv6, `Some(false)` for IPv4.
/// Ignore unsupported subtypes and families; reject bodies that are not four bytes.
pub fn refresh_family(b: &[u8], n: &Negotiated) -> Result<Option<bool>> {
    ensure!(b.len() == 4, "invalid ROUTE-REFRESH length");
    // Enhanced route refresh is not advertised. Ignore unknown subtypes/SAFIs.
    if b[2] != 0 || b[3] != 1 {
        return Ok(None);
    }
    match u16b(b) {
        1 if n.ipv4 => Ok(Some(false)),
        2 if n.ipv6 => Ok(Some(true)),
        _ => Ok(None),
    }
}
/// State-specific subcodes for unexpected messages, as defined by RFC 6608.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum FsmState {
    OpenSent = 1,
    OpenConfirm = 2,
    Established = 3,
}

/// Describe a peer NOTIFICATION without replying, or include state and type in an error.
pub fn unexpected(state: FsmState, kind: u8, body: &[u8]) -> anyhow::Error {
    if kind == 3 {
        if body.len() >= 2 {
            anyhow::anyhow!(
                "peer sent NOTIFICATION code={} subcode={}",
                body[0],
                body[1]
            )
        } else {
            anyhow::anyhow!("peer sent truncated NOTIFICATION")
        }
    } else {
        ProtocolError {
            code: 5,
            subcode: state as u8,
            data: vec![kind],
            reason: "unexpected message in BGP state",
        }
        .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Pair the example configuration with a peer and dual-stack, four-octet negotiation.
    fn fixture() -> (Config, Peer, Negotiated) {
        let c: Config = toml::from_str(include_str!("../examples/ubgp.toml")).unwrap();
        let p = c.peers[0].clone();
        let n = Negotiated {
            router_id: "192.0.2.2".parse().unwrap(),
            hold: 90,
            asn4: true,
            internal: false,
            ipv4: true,
            ipv6: true,
        };
        (c, p, n)
    }
    #[test]
    fn encode_ipv4_ipv6_announce_withdraw_and_eor() {
        let (c, mut p, n) = fixture();
        p.next_hop_v6 = Some("2001:db8::1".parse().unwrap());
        for prefix in ["0.0.0.0/0", "203.0.113.0/24", "2001:db8::/32", "::/0"] {
            for withdraw in [false, true] {
                let msg = update(&c, &p, &n, &[prefix.parse().unwrap()], withdraw);
                assert_eq!(u16b(&msg[16..]) as usize, msg.len());
                validate_update(&msg[19..], &n).unwrap();
            }
        }
        for v6 in [false, true] {
            validate_update(&end_of_rib(v6)[19..], &n).unwrap();
        }
    }
    #[test]
    fn legacy_as4_and_internal_aspath() {
        let (mut c, p, mut n) = fixture();
        c.asn = 4_200_000_001;
        n.asn4 = false;
        let packet = update(&c, &p, &n, &["10.0.0.0/8".parse().unwrap()], false);
        validate_update(&packet[19..], &n).unwrap();
        assert!(packet.windows(3).any(|b| b == [0xc0, 17, 6]));
        c.asn = p.remote_asn;
        let packet = update(&c, &p, &n, &["10.0.0.0/8".parse().unwrap()], false);
        assert!(packet.windows(3).any(|b| b == [0x40, 2, 0]));
        assert!(packet.windows(3).any(|b| b == [0x40, 5, 4]));
    }
    #[test]
    fn open_negotiation_checks_asn_hold_and_family() {
        let (c, p, _) = fixture();
        let mut remote = c.clone();
        remote.asn = p.remote_asn;
        remote.router_id = "192.0.2.2".parse().unwrap();
        let msg = open(&remote, &p);
        let n = parse_open(&msg[19..], &c, &p).unwrap();
        assert!(n.ipv4 && n.asn4);
        assert!(!n.ipv6);
        let mut msg = msg;
        msg[22..24].copy_from_slice(&1u16.to_be_bytes());
        assert!(parse_open(&msg[19..], &c, &p).is_err());
    }
    #[tokio::test]
    async fn framing_handles_fragmentation_and_rejects_oversize() {
        use tokio::io::AsyncWriteExt;
        let (mut a, mut b) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            for byte in frame(4, &[]) {
                a.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        assert_eq!(read_frame(&mut b).await.unwrap(), (4, vec![]));
        task.await.unwrap();
        let mut bad = frame(4, &[]);
        bad[16..18].copy_from_slice(&4097u16.to_be_bytes());
        assert!(read_frame(&mut bad.as_slice()).await.is_err());
    }
    #[test]
    fn maximum_ipv6_batch_fits_standard_message_size() {
        let (c, mut p, n) = fixture();
        p.next_hop_v6 = Some("2001:db8::1".parse().unwrap());
        p.next_hop_v6_link_local = Some("fe80::1".parse().unwrap());
        let prefixes = vec!["2001:db8::ff/128".parse().unwrap(); MAX_UPDATE_PREFIXES];
        for withdraw in [false, true] {
            let msg = update(&c, &p, &n, &prefixes, withdraw);
            assert!(msg.len() <= MAX_MESSAGE);
            validate_update(&msg[19..], &n).unwrap();
        }
    }
    #[test]
    fn arbitrary_protocol_input_does_not_panic() {
        let (c, p, n) = fixture();
        let mut state = 0x123456789abcdefu64;
        for len in 0..4096 {
            let mut bytes = vec![0u8; len];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let _ = parse_open(&bytes, &c, &p);
            let _ = validate_update(&bytes, &n);
            let _ = update_prefixes(&bytes);
        }
    }
    #[test]
    fn parsers_never_panic_on_truncated_input() {
        let (c, p, n) = fixture();
        let open = open(&c, &p);
        for l in 0..open.len() - 19 {
            assert!(parse_open(&open[19..19 + l], &c, &p).is_err());
        }
        let update = update(&c, &p, &n, &["10.0.0.0/8".parse().unwrap()], false);
        for l in 0..update.len() - 20 {
            let _ = validate_update(&update[19..19 + l], &n);
        }
        for l in 0..512 {
            let b = vec![255u8; l];
            let _ = validate_update(&b, &n);
        }
    }
    /// Build independent IPv4 UPDATE bytes with a known route and mandatory attributes.
    fn received_update(asn4: bool, extra: &[u8]) -> Vec<u8> {
        let mut attrs = vec![0x40, 1, 1, 2];
        if asn4 {
            attrs.extend_from_slice(&[0x40, 2, 6, 2, 1, 0, 0, 252, 1]);
        } else {
            attrs.extend_from_slice(&[0x40, 2, 4, 2, 1, 252, 1]);
        }
        attrs.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 2]);
        attrs.extend_from_slice(extra);
        let mut body = vec![0, 0];
        body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        body.extend(attrs);
        body.extend_from_slice(&[24, 10, 1, 0]);
        body
    }

    #[test]
    fn update_recovery_and_fatal_boundaries() {
        use UpdateAction::*;
        let (_, _, n) = fixture();
        let mut bad_origin = received_update(true, &[]);
        bad_origin[7] = 3;
        assert_eq!(validate_update(&bad_origin, &n).unwrap(), TreatAsWithdraw);
        assert_eq!(
            update_prefixes(&bad_origin),
            vec!["10.1.0.0/24".parse::<IpNet>().unwrap()]
        );
        // The first occurrence wins, even if a later duplicate is malformed.
        assert_eq!(
            validate_update(&received_update(true, &[0x40, 1, 1, 3]), &n).unwrap(),
            AttributeDiscard
        );
        for extra in [
            vec![0xc0, 8, 0],
            vec![0xc0, 16, 1, 0],
            vec![0xc0, 32, 0],
            vec![0x80, 4, 1, 0],
            vec![0x40, 8, 4, 0, 0, 0, 1],
            vec![0x80],
            vec![0x80, 8, 255],
        ] {
            assert_eq!(
                validate_update(&received_update(true, &extra), &n).unwrap(),
                TreatAsWithdraw,
                "{extra:?}"
            );
        }
        for extra in [vec![0x40, 6, 1, 0], vec![0xc0, 7, 1, 0], vec![0x80, 6, 0]] {
            assert_eq!(
                validate_update(&received_update(true, &extra), &n).unwrap(),
                AttributeDiscard
            );
        }
        // Missing mandatory attributes are recoverable only with reachable NLRI.
        assert_eq!(
            validate_update(&[0, 0, 0, 0, 24, 10, 1, 0], &n).unwrap(),
            TreatAsWithdraw
        );
        assert_eq!(validate_update(&[0, 0, 0, 0], &n).unwrap(), Valid);
        let mut without_nlri = bad_origin.clone();
        without_nlri.truncate(without_nlri.len() - 4);
        assert!(validate_update(&without_nlri, &n).is_err());
        let mut bad_nlri = bad_origin;
        *bad_nlri.last_mut().unwrap() = 0;
        let last = bad_nlri.len() - 4;
        bad_nlri[last] = 33;
        assert!(validate_update(&bad_nlri, &n).is_err());
        for extra in [
            vec![0x80, 14, 3, 0, 2, 1],
            vec![0x80, 15, 4, 0, 2, 1, 129],
            vec![0x80, 15, 3, 0, 2, 1, 0x80, 15, 3, 0, 2, 1],
            vec![0x40, 99, 1, 0],
        ] {
            assert!(
                validate_update(&received_update(true, &extra), &n).is_err(),
                "{extra:?}"
            );
        }
        // A later malformed MP attribute overrides an earlier recoverable error.
        let mut both = received_update(true, &[0x80, 14, 3, 0, 2, 1]);
        both[7] = 3;
        assert!(validate_update(&both, &n).is_err());
    }

    #[test]
    fn as4_attributes_and_external_only_discards_preserve_updates() {
        let (_, _, mut n) = fixture();
        for asn4 in [false, true] {
            n.asn4 = asn4;
            for extra in [vec![0xc0, 17, 1, 0], vec![0xc0, 18, 1, 0]] {
                assert_eq!(
                    validate_update(&received_update(asn4, &extra), &n).unwrap(),
                    UpdateAction::AttributeDiscard
                );
            }
        }
        n.asn4 = true;
        for kind in [5, 9, 10] {
            let extra = [0x80, kind, 1, 0];
            assert_eq!(
                validate_update(&received_update(true, &extra), &n).unwrap(),
                UpdateAction::AttributeDiscard
            );
            n.internal = true;
            assert_eq!(
                validate_update(&received_update(true, &extra), &n).unwrap(),
                UpdateAction::TreatAsWithdraw
            );
            n.internal = false;
        }
        n.internal = true;
        assert_eq!(
            validate_update(&received_update(true, &[]), &n).unwrap(),
            UpdateAction::TreatAsWithdraw
        );
        assert_eq!(
            validate_update(&received_update(true, &[0x40, 5, 4, 0, 0, 0, 100]), &n).unwrap(),
            UpdateAction::Valid
        );
    }
    #[test]
    fn open_accepts_integer_ids_and_equal_external_ids_only() {
        let (c, mut p, _) = fixture();
        for internal in [false, true] {
            if internal {
                p.remote_asn = c.asn;
            }
            for id in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.1"] {
                let mut remote = c.clone();
                remote.asn = p.remote_asn;
                remote.router_id = id.parse().unwrap();
                let packet = open(&remote, &p);
                let result = parse_open(&packet[19..], &c, &p);
                let rejected = id == "0.0.0.0" || (internal && remote.router_id == c.router_id);
                assert_eq!(result.is_err(), rejected, "{id}, internal={internal}");
                if rejected {
                    let error = result.unwrap_err();
                    let error = error.downcast_ref::<ProtocolError>().unwrap();
                    assert_eq!((error.code, error.subcode), (2, 3));
                }
            }
        }
    }
    /// Build an extended OPEN around explicitly supplied parameter bytes.
    fn extended_open(c: &Config, p: &Peer, params: &[u8]) -> Vec<u8> {
        let mut b = vec![4];
        b.extend_from_slice(&(p.remote_asn as u16).to_be_bytes());
        b.extend_from_slice(&90u16.to_be_bytes());
        b.extend_from_slice(&[192, 0, 2, 2]);
        assert_ne!(c.router_id.octets(), [192, 0, 2, 2]);
        b.extend_from_slice(&[255, 255]);
        b.extend_from_slice(&(params.len() as u16).to_be_bytes());
        b.extend_from_slice(params);
        b
    }

    #[test]
    fn extended_open_accepts_short_long_and_multiple_parameters() {
        let (c, p, _) = fixture();
        // Separate parameters for four-octet ASN and IPv4 MP capability.
        let mut params = vec![2, 0, 6, 65, 4];
        params.extend_from_slice(&p.remote_asn.to_be_bytes());
        params.extend_from_slice(&[2, 0, 6, 1, 4, 0, 1, 0, 1]);
        for legacy_length in [1, 254, 255] {
            let mut b = extended_open(&c, &p, &params);
            b[9] = legacy_length;
            let n = parse_open(&b, &c, &p).unwrap();
            assert!(n.asn4 && n.ipv4);
        }
        // A single parameter larger than 255 bytes, with one-byte capability lengths.
        let mut caps = vec![65, 4];
        caps.extend_from_slice(&p.remote_asn.to_be_bytes());
        caps.extend_from_slice(&[1, 4, 0, 1, 0, 1, 200, 250]);
        caps.extend([0; 250]);
        let mut params = vec![2];
        params.extend_from_slice(&(caps.len() as u16).to_be_bytes());
        params.extend(caps);
        let b = extended_open(&c, &p, &params);
        assert!(b.len() > 255);
        let n = parse_open(&b, &c, &p).unwrap();
        assert!(n.asn4 && n.ipv4);
        let empty = parse_open(&extended_open(&c, &p, &[]), &c, &p).unwrap();
        assert!(empty.ipv4 && !empty.asn4);
    }

    #[test]
    fn extended_open_rejects_truncation_and_inconsistent_nested_lengths() {
        let (c, p, _) = fixture();
        let b = extended_open(&c, &p, &[2, 0, 6, 1, 4, 0, 1, 0, 1]);
        for length in 0..b.len() {
            assert!(parse_open(&b[..length], &c, &p).is_err(), "{length}");
        }
        for (position, value) in [(9, 0), (12, 8), (12, 10), (15, 5), (15, 7), (17, 5)] {
            let mut bad = b.clone();
            bad[position] = value;
            assert!(parse_open(&bad, &c, &p).is_err(), "{position}={value}");
        }
    }
    #[test]
    fn multiprotocol_nlri_is_first_on_wire_but_legacy_order_is_accepted() {
        let (mut c, mut p, mut n) = fixture();
        p.next_hop_v6 = Some("2001:db8::1".parse().unwrap());
        p.next_hop_v6_link_local = Some("fe80::1".parse().unwrap());
        for internal in [false, true] {
            if internal {
                c.asn = p.remote_asn;
                n.internal = true;
            }
            for withdraw in [false, true] {
                let packet = update(
                    &c,
                    &p,
                    &n,
                    &["2001:db8:100::/48".parse().unwrap()],
                    withdraw,
                );
                let body = &packet[19..];
                assert_eq!(&body[..2], &[0, 0]);
                let len = u16b(&body[2..]) as usize;
                assert_eq!(body.len(), len + 4);
                let attrs = &body[4..];
                assert_eq!(attrs[0], 0x80);
                assert_eq!(attrs[1], if withdraw { 15 } else { 14 });
                assert_eq!(&attrs[3..6], &[0, 2, 1]);
                if !withdraw {
                    assert_eq!(attrs[6], 32); // Global plus link-local next hop.
                    let first_len = 3 + attrs[2] as usize;
                    assert_eq!(&attrs[first_len..first_len + 4], &[0x40, 1, 1, 2]);
                    let mut legacy = body[..4].to_vec();
                    legacy.extend_from_slice(&attrs[first_len..]);
                    legacy.extend_from_slice(&attrs[..first_len]);
                    assert_eq!(validate_update(&legacy, &n).unwrap(), UpdateAction::Valid);
                }
                assert_eq!(validate_update(body, &n).unwrap(), UpdateAction::Valid);
            }
        }
        assert_eq!(&end_of_rib(true)[19..], &[0, 0, 0, 6, 0x80, 15, 3, 0, 2, 1]);
    }
    /// Assert exact NOTIFICATION payload bytes, including RFC-required error data.
    fn notification_data(error: anyhow::Error, expected: &[u8]) {
        let e = error.downcast_ref::<ProtocolError>().unwrap();
        let packet = notification(e.code, e.subcode, &e.data);
        assert_eq!(&packet[..16], &[255; 16]);
        assert_eq!(u16b(&packet[16..]) as usize, 19 + expected.len());
        assert_eq!(packet[18], 3);
        assert_eq!(&packet[19..], expected);
    }

    #[test]
    fn notifications_include_capabilities_and_offending_attributes() {
        let (c, mut p, n) = fixture();
        let mut remote = c.clone();
        remote.asn = p.remote_asn;
        remote.router_id = "192.0.2.2".parse().unwrap();
        let packet = open(&remote, &p);
        p.ipv4 = false;
        p.ipv6 = true;
        notification_data(
            parse_open(&packet[19..], &c, &p).unwrap_err(),
            &[2, 7, 1, 4, 0, 2, 0, 1],
        );
        let mut remote_peer = p.clone();
        remote_peer.ipv4 = false;
        remote_peer.ipv6 = false;
        // Advertise an unsupported family so legacy IPv4 fallback does not apply.
        let mut unsupported = open(&remote, &remote_peer)[19..].to_vec();
        unsupported[9] += 6;
        unsupported[11] += 6;
        unsupported.extend_from_slice(&[1, 4, 0, 25, 0, 70]);
        p.ipv4 = true;
        notification_data(
            parse_open(&unsupported, &c, &p).unwrap_err(),
            &[2, 7, 1, 4, 0, 1, 0, 1, 1, 4, 0, 2, 0, 1],
        );
        for attr in [vec![0x40, 99, 1, 42], vec![0x50, 99, 0, 1, 42]] {
            let mut expected = vec![3, 2];
            expected.extend_from_slice(&attr);
            notification_data(
                validate_update(&received_update(true, &attr), &n).unwrap_err(),
                &expected,
            );
        }
        let mut optional = packet[19..29].to_vec();
        optional[9] = 3;
        optional.extend_from_slice(&[99, 1, 42]);
        notification_data(
            parse_open(&optional, &c, &p).unwrap_err(),
            &[2, 4, 99, 1, 42],
        );
    }

    #[test]
    fn fsm_notifications_identify_state_and_unexpected_message() {
        for (state, subcode, kind) in [
            (FsmState::OpenSent, 1, 4),
            (FsmState::OpenConfirm, 2, 2),
            (FsmState::Established, 3, 1),
        ] {
            notification_data(unexpected(state, kind, &[]), &[5, subcode, kind]);
            assert!(
                unexpected(state, 3, &[6, 0])
                    .downcast_ref::<ProtocolError>()
                    .is_none()
            );
        }
    }
}
