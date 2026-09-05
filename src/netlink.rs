//! Notifications are invalidations, not a second (potentially lossy) routing table.
//! One bounded, coalesced refresh rebuilds prefix presence from complete dumps.
use crate::config::Config;
use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use std::{
    collections::{HashMap, HashSet},
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::watch;
use tracing::{debug, info, warn};

pub type Prefixes = HashSet<IpNet>;
pub type Exports = HashMap<String, Arc<Prefixes>>;
const HEADER: usize = 16;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const NLMSG_DONE: u16 = 3;
const NLM_F_DUMP_INTR: u16 = 0x10;
const SOL_NETLINK: i32 = 270;
const NETLINK_GET_STRICT_CHK: i32 = 12;

fn align(n: usize) -> usize {
    (n + 3) & !3
}
fn u16n(b: &[u8]) -> u16 {
    u16::from_ne_bytes([b[0], b[1]])
}
fn u32n(b: &[u8]) -> u32 {
    u32::from_ne_bytes(b[..4].try_into().unwrap())
}

struct Socket {
    fd: OwnedFd,
}
impl Socket {
    fn open(groups: u32, buffer: usize) -> Result<Self> {
        // SAFETY: socket has no pointer arguments; a successful descriptor is owned here.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let s = Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        s.option(libc::SOL_SOCKET, libc::SO_RCVBUF, buffer as i32)?;
        let mut effective = 0i32;
        let mut len = mem::size_of_val(&effective) as libc::socklen_t;
        // SAFETY: both output pointers refer to initialized, writable objects of the stated size.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&mut effective as *mut i32).cast(),
                &mut len,
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        // Linux reports twice the requested capacity for bookkeeping.
        if groups != 0 {
            info!(
                requested = buffer,
                effective, "netlink receive buffer (effective includes Linux doubling)"
            );
            if (effective as usize) < buffer.saturating_mul(2) {
                warn!("netlink receive buffer capped; raise net.core.rmem_max to requested bytes");
            }
        }
        // SAFETY: zero is a valid initial representation of sockaddr_nl, including padding.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_groups = groups;
        // SAFETY: addr is a correctly sized sockaddr_nl, live for this call.
        if unsafe {
            libc::bind(
                fd,
                (&addr as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&addr) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(s)
    }
    fn option(&self, level: i32, option: i32, value: i32) -> Result<()> {
        // SAFETY: the value pointer is valid for the supplied length.
        if unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                level,
                option,
                (&value as *const i32).cast(),
                mem::size_of_val(&value) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: all pointers describe live writable storage. recvmsg cannot write past iov_len.
        unsafe {
            let mut addr: libc::sockaddr_nl = mem::zeroed();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            let mut msg: libc::msghdr = mem::zeroed();
            msg.msg_name = (&mut addr as *mut libc::sockaddr_nl).cast();
            msg.msg_namelen = mem::size_of_val(&addr) as _;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            let n = libc::recvmsg(self.fd.as_raw_fd(), &mut msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if msg.msg_flags & libc::MSG_TRUNC != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated netlink datagram",
                ));
            }
            if msg.msg_namelen != mem::size_of_val(&addr) as u32 || addr.nl_pid != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-kernel netlink sender",
                ));
            }
            Ok(n as usize)
        }
    }
    fn request(&self, seq: u32, family: u8, table: u32) -> Result<()> {
        let mut req = [0u8; 36];
        req[..4].copy_from_slice(&36u32.to_ne_bytes());
        req[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
        req[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
        req[8..12].copy_from_slice(&seq.to_ne_bytes());
        req[16] = family;
        req[28..30].copy_from_slice(&8u16.to_ne_bytes());
        req[30..32].copy_from_slice(&15u16.to_ne_bytes()); // RTA_TABLE
        req[32..36].copy_from_slice(&table.to_ne_bytes());
        // SAFETY: sockaddr and input buffer remain alive for sendto.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let n = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                req.as_ptr().cast(),
                req.len(),
                0,
                (&addr as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&addr) as _,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error().into());
        }
        ensure!(n as usize == req.len(), "short netlink request");
        Ok(())
    }
}

#[derive(Debug)]
struct Message<'a> {
    kind: u16,
    flags: u16,
    seq: u32,
    payload: &'a [u8],
}
fn messages(mut bytes: &[u8], mut f: impl FnMut(Message<'_>) -> Result<()>) -> Result<()> {
    while !bytes.is_empty() {
        ensure!(bytes.len() >= HEADER, "short netlink header");
        let len = u32n(bytes) as usize;
        ensure!(
            len >= HEADER && len <= bytes.len(),
            "invalid netlink message length"
        );
        f(Message {
            kind: u16n(&bytes[4..]),
            flags: u16n(&bytes[6..]),
            seq: u32n(&bytes[8..]),
            payload: &bytes[HEADER..len],
        })?;
        if len == bytes.len() {
            break;
        }
        ensure!(align(len) <= bytes.len(), "short netlink padding");
        bytes = &bytes[align(len)..];
    }
    Ok(())
}

fn route(payload: &[u8], tables: &[u32]) -> Result<Option<IpNet>> {
    ensure!(payload.len() >= 12, "short rtmsg");
    let family = payload[0];
    if family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8 {
        return Ok(None);
    }
    // Only ordinary, destination-only unicast routes. No local/broadcast,
    // blackhole, prohibit, unreachable, cache clones, or source-specific routes.
    if payload[7] != 1 || payload[2] != 0 || u32n(&payload[8..]) & 0x200 != 0 {
        return Ok(None);
    }
    let width = if family == libc::AF_INET as u8 { 4 } else { 16 };
    ensure!(
        payload[1] as usize <= width * 8,
        "invalid route prefix length"
    );
    let mut table = payload[4] as u32;
    let mut dst = [0u8; 16];
    let mut has_dst = false;
    let mut attrs = &payload[12..];
    while !attrs.is_empty() {
        ensure!(attrs.len() >= 4, "short route attribute");
        let n = u16n(attrs) as usize;
        ensure!(n >= 4 && n <= attrs.len(), "invalid route attribute length");
        match u16n(&attrs[2..]) & 0x3fff {
            1 => {
                ensure!(n == width + 4, "invalid RTA_DST");
                dst[..width].copy_from_slice(&attrs[4..n]);
                has_dst = true;
            }
            15 => {
                ensure!(n == 8, "invalid RTA_TABLE");
                table = u32n(&attrs[4..]);
            }
            _ => {}
        }
        if n == attrs.len() {
            break;
        }
        ensure!(align(n) <= attrs.len(), "short route attribute padding");
        attrs = &attrs[align(n)..];
    }
    ensure!(payload[1] == 0 || has_dst, "missing route destination");
    if !tables.contains(&table) {
        return Ok(None);
    }
    let ip = if width == 4 {
        IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(dst))
    };
    Ok(Some(IpNet::new(ip, payload[1])?.trunc()))
}

#[derive(Default, Debug)]
struct Events {
    changed: bool,
    lost: bool,
    datagrams: u64,
}
fn drain(events: &Socket, buf: &mut [u8]) -> Events {
    let mut result = Events::default();
    // Bound each pass for fairness with dump processing, shutdown and stale timers.
    for _ in 0..128 {
        match events.recv(buf) {
            Ok(n) => {
                result.datagrams += 1;
                if n == 0 {
                    result.lost = true;
                    break;
                }
                if messages(&buf[..n], |m| {
                    match m.kind {
                        4 | 2 => result.lost = true, // OVERRUN / ERROR
                        16..=28 | 104..=106 => result.changed = true,
                        _ => {}
                    }
                    Ok(())
                })
                .is_err()
                {
                    result.lost = true;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                result.lost = true;
                break;
            }
        }
    }
    result
}

fn poll(events: &Socket, dump: Option<&Socket>, millis: i32) -> Result<()> {
    let mut fds = [
        libc::pollfd {
            fd: events.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: dump.map_or(-1, |s| s.fd.as_raw_fd()),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: fds is writable storage for exactly two pollfd structures.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, millis) };
    if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        return Err(io::Error::last_os_error().into());
    }
    ensure!(
        fds.iter()
            .all(|f| f.revents & (libc::POLLNVAL | libc::POLLHUP) == 0),
        "netlink socket closed"
    );
    Ok(())
}

fn dump_status(payload: &[u8], saw_route: bool) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }
    ensure!(payload.len() >= 4, "short netlink dump status");
    let code = i32::from_ne_bytes(payload[..4].try_into().unwrap());
    ensure!(
        code == 0 || (code == -libc::ENOENT && !saw_route),
        "netlink dump failed: {}",
        io::Error::from_raw_os_error(code.saturating_neg())
    );
    Ok(())
}

fn snapshot(
    cfg: &Config,
    events: &Socket,
    stop: &AtomicBool,
    buf: &mut [u8],
    seq: &mut u32,
) -> Result<(Prefixes, bool)> {
    // A fresh request socket isolates timed-out dumps and old sequence numbers.
    let socket = Socket::open(0, cfg.kernel.receive_buffer_bytes)?;
    socket
        .option(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)
        .context("strict table dumps require Linux >= 4.20")?;
    let mut result = Prefixes::new();
    let mut changed = false;
    let started = Instant::now();
    for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
        if family == libc::AF_INET6 as u8 && !cfg.ipv6 {
            continue;
        }
        for &table in &cfg.kernel.tables {
            *seq = seq.wrapping_add(1).max(1);
            socket.request(*seq, family, table)?;
            let mut done = false;
            let mut saw_route = false;
            while !done {
                ensure!(!stop.load(Ordering::Relaxed), "stopping");
                ensure!(
                    started.elapsed() < Duration::from_secs(cfg.kernel.dump_timeout_secs),
                    "netlink dump deadline exceeded"
                );
                let ev = drain(events, buf);
                ensure!(!ev.lost, "netlink notification loss during dump");
                changed |= ev.changed;
                for _ in 0..128 {
                    match socket.recv(buf) {
                        Ok(n) => {
                            ensure!(n != 0, "empty dump datagram");
                            messages(&buf[..n], |m| {
                                ensure!(m.seq == *seq, "unexpected dump sequence");
                                ensure!(m.flags & NLM_F_DUMP_INTR == 0, "interrupted netlink dump");
                                match m.kind {
                                    NLMSG_DONE => {
                                        dump_status(m.payload, saw_route)?;
                                        done = true;
                                    }
                                    2 => {
                                        ensure!(m.payload.len() >= 4, "short NLMSG_ERROR");
                                        let code =
                                            i32::from_ne_bytes(m.payload[..4].try_into().unwrap());
                                        // A configured table need not exist yet. Linux
                                        // reports ENOENT for some empty family/table
                                        // combinations; later route creation notifies us.
                                        if code == -libc::ENOENT && !saw_route {
                                            done = true;
                                        } else if code != 0 {
                                            bail!(
                                                "netlink dump: {}",
                                                io::Error::from_raw_os_error(code.saturating_neg())
                                            );
                                        }
                                    }
                                    4 => bail!("netlink dump overrun"),
                                    RTM_NEWROUTE => {
                                        saw_route = true;
                                        if let Some(prefix) = route(m.payload, &cfg.kernel.tables)?
                                        {
                                            result.insert(prefix);
                                            ensure!(
                                                result.len() <= cfg.kernel.max_prefixes,
                                                "max_prefixes exceeded; refusing partial export"
                                            );
                                        }
                                    }
                                    _ => {}
                                }
                                Ok(())
                            })?;
                            if done {
                                break;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e.into()),
                    }
                }
                if !done {
                    poll(events, Some(&socket), 50)?;
                }
            }
        }
    }
    // Capture queued notifications/loss at the publication boundary too.
    let ev = drain(events, buf);
    ensure!(!ev.lost, "netlink notification loss at end of dump");
    Ok((result, changed || ev.changed))
}

pub fn filter(cfg: &Config, prefixes: &Prefixes) -> Exports {
    cfg.peers
        .iter()
        .map(|p| &p.export_acl)
        .collect::<HashSet<_>>()
        .into_iter()
        .map(|name| {
            let acl = &cfg.acls[name];
            (
                name.clone(),
                Arc::new(
                    prefixes
                        .iter()
                        .filter(|p| acl.permits(p))
                        .copied()
                        .collect(),
                ),
            )
        })
        .collect()
}

#[derive(Debug)]
struct Freshness {
    dirty_since: Option<Instant>,
    withdrawn: bool,
}
impl Freshness {
    fn invalidate(&mut self, now: Instant) {
        self.dirty_since.get_or_insert(now);
    }
    fn expire(&mut self, now: Instant, limit: Duration, tx: &watch::Sender<Arc<Exports>>) {
        if !self.withdrawn
            && self
                .dirty_since
                .is_some_and(|start| now.duration_since(start) >= limit)
        {
            tx.send_replace(Arc::new(Exports::new()));
            self.withdrawn = true;
            warn!("kernel state stale; withdrawing all exports until a complete dump succeeds");
        }
    }
    fn publish(
        &mut self,
        now: Instant,
        changed: bool,
        tx: &watch::Sender<Arc<Exports>>,
        exports: Arc<Exports>,
    ) {
        if *tx.borrow() != exports {
            tx.send_replace(exports);
        }
        self.dirty_since = changed.then_some(now);
        self.withdrawn = false;
    }
}

struct Watchdog {
    quit: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Watchdog {
    fn drop(&mut self) {
        self.quit.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}

/// All memory queues are constant-size; route storage is capped by max_prefixes.
/// Watch channels retain only the latest complete export, shared among peers.
pub fn run(cfg: Arc<Config>, tx: watch::Sender<Arc<Exports>>, stop: Arc<AtomicBool>) -> Result<()> {
    let groups = 1 | 0x10 | 0x40 | if cfg.ipv6 { 0x100 | 0x400 } else { 0 };
    let events = Socket::open(groups, cfg.kernel.receive_buffer_bytes)
        .context("subscribing to rtnetlink")?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut seq = 0;
    let mut due = Instant::now();
    let mut dirty_since = Some(due);
    let freshness = Arc::new(Mutex::new(Freshness {
        dirty_since,
        withdrawn: false,
    }));
    // Independent deadline enforcement, including while a dump is blocked or
    // ACL evaluation is busy. Serialize expiry and publication to prevent races.
    let quit = Arc::new(AtomicBool::new(false));
    let q = quit.clone();
    let health = freshness.clone();
    let output = tx.clone();
    let limit = Duration::from_secs(cfg.kernel.stale_timeout_secs);
    let thread = std::thread::Builder::new()
        .name("ubgp-stale".into())
        .spawn(move || {
            while !q.load(Ordering::Relaxed) {
                health
                    .lock()
                    .unwrap()
                    .expire(Instant::now(), limit, &output);
                std::thread::park_timeout(Duration::from_millis(100));
            }
        })?;
    let _watchdog = Watchdog {
        quit,
        thread: Some(thread),
    };
    let mut retries = 0u32;
    let mut dumps = 0u64;
    let mut losses = 0u64;
    let mut datagrams = 0u64;
    let mut periodic = due;
    while !stop.load(Ordering::Relaxed) {
        let ev = drain(&events, &mut buf);
        datagrams += ev.datagrams;
        let now = Instant::now();
        if ev.changed || ev.lost || now >= periodic {
            dirty_since.get_or_insert(now);
            freshness.lock().unwrap().invalidate(now);
            if ev.lost {
                losses += 1;
                warn!(
                    losses,
                    "netlink loss detected; scheduling full resynchronization"
                );
            }
        }
        if dirty_since.is_some() && now >= due {
            let started = Instant::now();
            match snapshot(&cfg, &events, &stop, &mut buf, &mut seq) {
                Ok((prefixes, changed)) => {
                    dumps += 1;
                    let exports = Arc::new(filter(&cfg, &prefixes));
                    let after = drain(&events, &mut buf);
                    datagrams += after.datagrams;
                    if after.lost {
                        losses += 1;
                        warn!(
                            losses,
                            "netlink loss during ACL evaluation; discarding snapshot"
                        );
                        due =
                            Instant::now() + Duration::from_millis(cfg.kernel.refresh_interval_ms);
                        continue;
                    }
                    let changed = changed || after.changed;
                    freshness
                        .lock()
                        .unwrap()
                        .publish(Instant::now(), changed, &tx, exports);
                    debug!(
                        dumps,
                        prefixes = prefixes.len(),
                        elapsed_ms = started.elapsed().as_millis(),
                        losses,
                        datagrams,
                        changed_during_dump = changed,
                        "kernel snapshot reconciled"
                    );
                    retries = 0;
                    let end = Instant::now();
                    dirty_since = changed.then_some(end);
                    periodic = end + Duration::from_secs(cfg.kernel.reconcile_interval_secs);
                    due = end + Duration::from_millis(cfg.kernel.refresh_interval_ms);
                }
                Err(error) => {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    retries = retries.saturating_add(1);
                    warn!(%error, retries, "discarding incomplete kernel snapshot; retrying");
                    // Never let repeated failed dumps move the stale deadline forward.
                    due = Instant::now()
                        + Duration::from_millis((100u64 << retries.min(5)).min(3000));
                }
            }
        }
        poll(&events, None, 50)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_table_status_is_distinct_from_failed_partial_dump() {
        assert!(dump_status(&[], false).is_ok());
        assert!(dump_status(&0i32.to_ne_bytes(), true).is_ok());
        assert!(dump_status(&(-libc::ENOENT).to_ne_bytes(), false).is_ok());
        assert!(dump_status(&(-libc::ENOENT).to_ne_bytes(), true).is_err());
        assert!(dump_status(&(-libc::EINVAL).to_ne_bytes(), false).is_err());
        assert!(dump_status(&[0], false).is_err());
    }
    #[test]
    fn failed_refreshes_do_not_extend_stale_deadline() {
        let now = Instant::now();
        let prefixes: Prefixes = ["10.0.0.0/24".parse().unwrap()].into_iter().collect();
        let exports = Arc::new(HashMap::from([("export".into(), Arc::new(prefixes))]));
        let (tx, rx) = watch::channel(exports.clone());
        let mut health = Freshness {
            dirty_since: None,
            withdrawn: false,
        };
        health.invalidate(now);
        health.expire(now + Duration::from_secs(2), Duration::from_secs(3), &tx);
        assert_eq!(*rx.borrow(), exports);
        health.invalidate(now + Duration::from_secs(2));
        health.expire(now + Duration::from_secs(3), Duration::from_secs(3), &tx);
        assert!(rx.borrow().is_empty());
        health.publish(now + Duration::from_secs(4), false, &tx, exports.clone());
        health.expire(now + Duration::from_secs(100), Duration::from_secs(3), &tx);
        assert_eq!(*rx.borrow(), exports);
    }
    fn rt(table: u32, prefix: &str) -> Vec<u8> {
        let net: IpNet = prefix.parse().unwrap();
        let ip = match net.addr() {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        let mut b = vec![0u8; 12];
        b[0] = if ip.len() == 4 { 2 } else { 10 };
        b[1] = net.prefix_len();
        b[7] = 1;
        b.extend_from_slice(&8u16.to_ne_bytes());
        b.extend_from_slice(&15u16.to_ne_bytes());
        b.extend_from_slice(&table.to_ne_bytes());
        b.extend_from_slice(&((ip.len() + 4) as u16).to_ne_bytes());
        b.extend_from_slice(&1u16.to_ne_bytes());
        b.extend(ip);
        b
    }
    #[test]
    fn selected_tables_families_defaults_and_route_types() {
        for p in ["0.0.0.0/0", "10.1.0.0/16", "::/0", "2001:db8::/32"] {
            let mut b = rt(1000, p);
            assert_eq!(route(&b, &[1000]).unwrap(), Some(p.parse().unwrap()));
            assert_eq!(route(&b, &[254]).unwrap(), None);
            b[7] = 6;
            assert_eq!(route(&b, &[1000]).unwrap(), None);
        }
    }
    #[test]
    fn duplicates_across_tables_do_not_withdraw_remaining_route() {
        let rows = [rt(100, "10.0.0.0/24"), rt(200, "10.0.0.0/24")];
        let before: Prefixes = rows
            .iter()
            .filter_map(|b| route(b, &[100, 200]).unwrap())
            .collect();
        let after: Prefixes = rows[1..]
            .iter()
            .filter_map(|b| route(b, &[100, 200]).unwrap())
            .collect();
        assert_eq!(before, after);
    }
    #[test]
    fn malformed_datagrams_and_attributes_are_errors() {
        for n in 1..16 {
            assert!(messages(&vec![0; n], |_| Ok(())).is_err());
        }
        let mut b = rt(254, "10.0.0.0/8");
        b[12] = 255;
        assert!(route(&b, &[254]).is_err());
    }
    #[test]
    #[ignore = "scale benchmark; run with --ignored --nocapture"]
    fn million_route_snapshot() {
        let start = Instant::now();
        let mut prefixes = Prefixes::new();
        for n in 0..1_000_000u32 {
            let p = IpNet::new(IpAddr::V4(Ipv4Addr::from(0x0a000000 + n)), 32).unwrap();
            let row = rt(254, &p.to_string());
            prefixes.insert(route(&row, &[254]).unwrap().unwrap());
        }
        assert_eq!(prefixes.len(), 1_000_000);
        eprintln!(
            "million routes decoded/deduplicated in {:?}",
            start.elapsed()
        );
    }
}
