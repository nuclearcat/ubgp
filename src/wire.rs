//! Small bounded BGP codec. No received route is installed or re-exported.
use crate::config::{Config, Peer, valid_v4};
use anyhow::{Result, ensure};
use ipnet::IpNet;
use std::{fmt, net::Ipv4Addr};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const MAX_MESSAGE: usize = 4096;
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

pub fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() + 19 <= MAX_MESSAGE);
    let mut out = vec![255u8; 16];
    out.extend_from_slice(&((body.len() + 19) as u16).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}
pub fn notification(code: u8, subcode: u8, data: &[u8]) -> Vec<u8> {
    let mut b = vec![code, subcode];
    b.extend_from_slice(&data[..data.len().min(MAX_MESSAGE - 21)]);
    frame(3, &b)
}
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
    pub ipv4: bool,
    pub ipv6: bool,
}
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
        valid_v4(router_id) && router_id != cfg.router_id,
        2,
        3,
        "invalid or duplicate router ID",
    )?;
    require(
        b[9] as usize + 10 == b.len(),
        2,
        0,
        "invalid OPEN parameter length",
    )?;
    let mut params = &b[10..];
    let mut as4 = None;
    let mut mp = false;
    let mut v4 = false;
    let mut v6 = false;
    while !params.is_empty() {
        require(
            params.len() >= 2 && params[1] as usize + 2 <= params.len(),
            2,
            0,
            "invalid optional parameter",
        )?;
        require(params[0] == 2, 2, 4, "unsupported optional parameter")?;
        let mut caps = &params[2..2 + params[1] as usize];
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
        params = &params[2 + params[1] as usize..];
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
        ipv4: p.ipv4 && (v4 || !mp),
        ipv6: p.ipv6 && v6,
    };
    require(n.ipv4 || n.ipv6, 2, 7, "no common address family")?;
    Ok(n)
}

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
fn nlri(out: &mut Vec<u8>, p: &IpNet) {
    out.push(p.prefix_len());
    let n = (p.prefix_len() as usize).div_ceil(8);
    match p {
        IpNet::V4(p) => out.extend_from_slice(&p.network().octets()[..n]),
        IpNet::V6(p) => out.extend_from_slice(&p.network().octets()[..n]),
    }
}
pub fn update(
    cfg: &Config,
    p: &Peer,
    n: &Negotiated,
    prefixes: &[IpNet],
    withdraw: bool,
) -> Vec<u8> {
    assert!(!prefixes.is_empty() && prefixes.len() <= 200);
    let v6 = prefixes[0].addr().is_ipv6();
    assert!(prefixes.iter().all(|p| p.addr().is_ipv6() == v6));
    let mut encoded = Vec::new();
    for prefix in prefixes {
        nlri(&mut encoded, prefix);
    }
    let mut attrs = Vec::new();
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
pub fn end_of_rib(v6: bool) -> Vec<u8> {
    if v6 {
        frame(UPDATE, &[0, 0, 0, 6, 0x80, 15, 3, 0, 2, 1])
    } else {
        frame(UPDATE, &[0, 0, 0, 0])
    }
}

fn validate_nlri(mut b: &[u8], bits: usize) -> Result<()> {
    while !b.is_empty() {
        let n = (b[0] as usize).div_ceil(8);
        require(b[0] as usize <= bits && n < b.len(), 3, 10, "invalid NLRI")?;
        b = &b[n + 1..];
    }
    Ok(())
}
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
pub fn validate_update(b: &[u8], n: &Negotiated) -> Result<()> {
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
    while !attrs.is_empty() {
        require(attrs.len() >= 3, 3, 1, "short attribute")?;
        let flags = attrs[0];
        let kind = attrs[1] as usize;
        let h = if flags & 0x10 != 0 { 4 } else { 3 };
        require(attrs.len() >= h, 3, 1, "short extended attribute")?;
        let l = if h == 4 {
            u16b(&attrs[2..]) as usize
        } else {
            attrs[2] as usize
        };
        require(h + l <= attrs.len(), 3, 5, "truncated attribute")?;
        require(!seen[kind], 3, 1, "duplicate attribute")?;
        seen[kind] = true;
        let data = &attrs[h..h + l];
        let expected = match kind {
            1 | 2 | 3 | 5 | 6 => Some(0x40),
            4 | 9 | 10 | 14 | 15 => Some(0x80),
            7 | 8 | 16 | 17 | 18 | 32 => Some(0xc0),
            _ => None,
        };
        if let Some(expected) = expected {
            require(
                flags & 0xc0 == expected && (flags & 0x20 == 0 || expected == 0xc0),
                3,
                4,
                "invalid attribute flags",
            )?;
        }
        match kind {
            1 => require(l == 1 && data[0] <= 2, 3, 6, "invalid ORIGIN")?,
            2 => validate_path(data, if n.asn4 { 4 } else { 2 })?,
            3 => require(
                l == 4 && valid_v4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                3,
                8,
                "invalid NEXT_HOP",
            )?,
            4 | 5 | 9 => require(l == 4, 3, 5, "invalid four-byte attribute")?,
            6 => require(l == 0, 3, 5, "invalid ATOMIC_AGGREGATE")?,
            7 => require(l == if n.asn4 { 8 } else { 6 }, 3, 5, "invalid AGGREGATOR")?,
            8 | 10 => require(l % 4 == 0, 3, 5, "invalid community/cluster list")?,
            16 => require(l % 8 == 0, 3, 5, "invalid extended communities")?,
            17 => validate_path(data, 4)?,
            18 => require(l == 8, 3, 5, "invalid AS4_AGGREGATOR")?,
            32 => require(l % 12 == 0, 3, 5, "invalid large communities")?,
            14 | 15 => {
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
                    mp_reach |= start < l;
                }
                if data[2] == 1 && (afi == 1 || afi == 2) {
                    validate_nlri(&data[start..], if afi == 1 { 32 } else { 128 })?;
                }
            }
            _ => require(flags & 0x80 != 0, 3, 2, "unknown well-known attribute")?,
        }
        attrs = &attrs[h + l..];
    }
    if !tail.is_empty() || mp_reach {
        for kind in [1, 2] {
            if !seen[kind] {
                return Err(ProtocolError {
                    code: 3,
                    subcode: 3,
                    data: vec![kind as u8],
                    reason: "missing mandatory attribute",
                }
                .into());
            }
        }
    }
    if !tail.is_empty() && !seen[3] {
        return Err(ProtocolError {
            code: 3,
            subcode: 3,
            data: vec![3],
            reason: "missing NEXT_HOP",
        }
        .into());
    }
    Ok(())
}
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
pub fn unexpected(kind: u8) -> anyhow::Error {
    if kind == 3 {
        anyhow::anyhow!("peer sent NOTIFICATION")
    } else {
        err(5, 0, "unexpected message in BGP state")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Config, Peer, Negotiated) {
        let c: Config = toml::from_str(include_str!("../examples/ubgp.toml")).unwrap();
        let p = c.peers[0].clone();
        let n = Negotiated {
            router_id: "192.0.2.2".parse().unwrap(),
            hold: 90,
            asn4: true,
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
        let prefixes = vec!["2001:db8::ff/128".parse().unwrap(); 200];
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
}
