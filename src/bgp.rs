use crate::{
    config::{Config, Peer},
    management::{self, Status},
    netlink::{Exports, Prefixes},
    transport::endpoint,
    wire::{self, Negotiated, ProtocolError},
};
use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::{
    collections::{HashMap, VecDeque},
    ffi::{CStr, CString},
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::{Notify, mpsc, watch},
    task::JoinSet,
    time::{Instant, sleep, sleep_until, timeout},
};
use tracing::{debug, info, warn};

/// Resolve the peering interface to its kernel index, failing if it is absent.
fn index(p: &Peer) -> Result<u32> {
    let name = CString::new(p.interface.as_str())?;
    // SAFETY: name is a terminated C string for the duration of the call.
    let n = unsafe { libc::if_nametoindex(name.as_ptr()) };
    ensure!(n != 0, "interface {} does not exist", p.interface);
    Ok(n)
}
/// Bind traffic to the peering interface, limit it to one hop, and disable Nagle.
fn configure(socket: &SockRef<'_>, p: &Peer) -> Result<()> {
    socket
        .bind_device(Some(p.interface.as_bytes()))
        .context("binding BGP socket to interface")?;
    if p.address.is_ipv4() {
        socket.set_ttl_v4(1)?;
    } else {
        socket.set_unicast_hops_v6(1)?;
    }
    socket.set_tcp_nodelay(true)?;
    Ok(())
}

/// Verify local and next-hop addresses and return an interface link-local address.
///
/// Explicit next-hop overrides must still be addresses belonging to this router
/// on the peering interface. Configuration cannot silently become third-party NH.
fn check_local_addresses(p: &Peer) -> Result<Option<std::net::Ipv6Addr>> {
    let mut root = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes root on success; guard frees the entire list.
    if unsafe { libc::getifaddrs(&mut root) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    struct Guard(*mut libc::ifaddrs);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = Guard(root);
    let mut ips = Vec::new();
    let mut node = root;
    while !node.is_null() {
        // SAFETY: nodes, interface names and family-specific addresses are provided
        // by getifaddrs and remain valid until the guard is dropped.
        unsafe {
            let a = &*node;
            if !a.ifa_addr.is_null()
                && CStr::from_ptr(a.ifa_name).to_bytes() == p.interface.as_bytes()
            {
                match (*a.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let a = &*a.ifa_addr.cast::<libc::sockaddr_in>();
                        ips.push(IpAddr::V4(std::net::Ipv4Addr::from(
                            a.sin_addr.s_addr.to_ne_bytes(),
                        )));
                    }
                    libc::AF_INET6 => {
                        let a = &*a.ifa_addr.cast::<libc::sockaddr_in6>();
                        ips.push(IpAddr::V6(std::net::Ipv6Addr::from(a.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            node = a.ifa_next;
        }
    }
    ensure!(
        ips.contains(&p.local_address),
        "local_address is not assigned to {}",
        p.interface
    );
    if p.ipv4 {
        ensure!(
            p.nh4().is_some_and(|a| ips.contains(&IpAddr::V4(a))),
            "IPv4 next hop is not assigned to {}",
            p.interface
        );
    }
    if p.ipv6 {
        ensure!(
            p.nh6().is_some_and(|a| ips.contains(&IpAddr::V6(a))),
            "IPv6 next hop is not assigned to {}",
            p.interface
        );
    }
    if let Some(a) = p.next_hop_v6_link_local {
        ensure!(
            ips.contains(&IpAddr::V6(a)),
            "link-local next hop is not assigned to {}",
            p.interface
        );
    }
    Ok(ips.iter().find_map(|ip| match ip {
        IpAddr::V6(a) if a.is_unicast_link_local() => Some(*a),
        _ => None,
    }))
}

/// Connect from the configured local address with optional TCP-MD5 and a deadline.
async fn connect(p: &Peer) -> Result<TcpStream> {
    info!(peer = %p.address, local = %p.local_address, interface = %p.interface, port = p.port, md5 = p.md5_password.is_some(), "BGP Connect: starting outgoing TCP connection");
    let idx = index(p)?;
    let socket = if p.address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    configure(&SockRef::from(&socket), p)?;
    socket
        .bind(endpoint(p.local_address, 0, idx))
        .context("binding local TCP address")?;
    crate::tcp_md5::install(&socket, p, idx)?;
    timeout(
        Duration::from_secs(p.connect_timeout_secs),
        socket.connect(endpoint(p.address, p.port, idx)),
    )
    .await
    .with_context(|| format!("TCP connect timed out after {}s", p.connect_timeout_secs))?
    .context("TCP connect failed")
}
/// Write a complete packet within the deadline; an error may leave a partial frame.
async fn send(writer: &mut (impl AsyncWrite + Unpin), packet: &[u8], seconds: u64) -> Result<()> {
    timeout(Duration::from_secs(seconds), writer.write_all(packet))
        .await
        .context("BGP write deadline exceeded")??;
    Ok(())
}
/// Best-effort send a NOTIFICATION for protocol errors, allowing at most one second.
async fn report(writer: &mut (impl AsyncWrite + Unpin), error: &anyhow::Error) {
    if let Some(e) = error.downcast_ref::<ProtocolError>() {
        let _ = send(writer, &wire::notification(e.code, e.subcode, &e.data), 1).await;
    }
}
struct Candidate {
    stream: TcpStream,
    negotiated: Negotiated,
    incoming: bool,
    link_local: Option<std::net::Ipv6Addr>,
}
/// Check local addresses and exchange OPENs within the connection timeout.
/// The returned candidate still needs KEEPALIVE confirmation to become established.
async fn handshake(
    mut stream: TcpStream,
    cfg: Arc<Config>,
    p: Peer,
    incoming: bool,
) -> Result<Candidate> {
    info!(peer = %p.address, incoming, "BGP TCP connected");
    configure(&SockRef::from(&stream), &p)?;
    let link_local = check_local_addresses(&p)?;
    let result = async {
        send(&mut stream, &wire::open(&cfg, &p), p.write_timeout_secs).await?;
        info!(peer = %p.address, incoming, "BGP OpenSent: waiting for peer OPEN");
        let (kind, body) = wire::read_frame(&mut stream).await?;
        if kind != 1 {
            return Err(wire::unexpected(kind, &body));
        }
        wire::parse_open(&body, &cfg, &p)
    };
    match timeout(Duration::from_secs(p.connect_timeout_secs), result).await {
        Ok(Ok(negotiated)) => Ok(Candidate {
            stream,
            negotiated,
            incoming,
            link_local,
        }),
        Ok(Err(e)) => {
            report(&mut stream, &e).await;
            Err(e)
        }
        Err(_) => bail!("OPEN timeout"),
    }
}

/// Select an incoming or outgoing OPEN candidate using the router-ID preference.
/// Allow a short collision window for the other direction; abort unused candidates.
async fn choose(
    cfg: Arc<Config>,
    p: Peer,
    incoming: &mut mpsc::Receiver<TcpStream>,
) -> Result<Candidate> {
    let mut tasks = JoinSet::new();
    let c = cfg.clone();
    let peer = p.clone();
    tasks.spawn(async move {
        let stream = connect(&peer).await.context("outgoing TCP setup")?;
        handshake(stream, c, peer, false)
            .await
            .context("outgoing BGP OPEN exchange")
    });
    let mut errors = Vec::with_capacity(2);
    let mut pending: Option<Candidate> = None;
    let mut deadline = Instant::now() + Duration::from_secs(p.connect_timeout_secs + 2);
    let mut incoming_started = false;
    loop {
        tokio::select! {
            stream = incoming.recv(), if !incoming_started => {
                let Some(stream) = stream else { bail!("incoming listener stopped"); };
                incoming_started = true;
                let c = cfg.clone();
                let peer = p.clone();
                tasks.spawn(async move {
                    handshake(stream, c, peer, true).await.context("incoming BGP OPEN exchange")
                });
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result.context("missing connection task")?? {
                    Ok(candidate) => {
                        // RFC 4271 collision preference: the larger BGP ID keeps
                        // the connection it initiated. Give a concurrent OPEN a
                        // short settling window before using the other direction.
                        let prefer_incoming = cfg.router_id < candidate.negotiated.router_id;
                        if candidate.incoming == prefer_incoming {
                            if let Some(mut old) = pending.take() { let _ = send(&mut old.stream,&wire::notification(6,7,&[]),1).await; }
                            return Ok(candidate);
                        }
                        pending = Some(candidate);
                        deadline = Instant::now() + Duration::from_millis(500);
                    }
                    Err(e) => {
                        debug!(peer = %p.address, e = %format!("{e:#}"), "connection candidate failed");
                        errors.push(format!("{e:#}"));
                    }
                }
                if tasks.is_empty() && pending.is_none() && incoming_started {
                    bail!("both connection candidates failed: {}", errors.join("; "));
                }
            }
            _ = sleep_until(deadline) => {
                if let Some(candidate) = pending.take() { return Ok(candidate); }
                let incoming_status = if incoming_started { "incoming candidate did not establish" } else { "no incoming TCP connection received" };
                if errors.is_empty() { errors.push("connection attempt still pending at selection deadline".into()); }
                bail!("no usable BGP connection: {}; {incoming_status}", errors.join("; "));
            }
        }
    }
    // Dropping JoinSet aborts all unused candidates and closes their sockets.
}

/// Coalesce refresh requests by address family without losing requests during cooldown.
#[derive(Default)]
struct Refresh {
    pending: AtomicU8,
    ready: Notify,
}
impl Refresh {
    fn request(&self, v6: bool) {
        self.pending
            .fetch_or(if v6 { 2 } else { 1 }, Ordering::Relaxed);
        self.ready.notify_one();
    }
}

/// Validate inbound messages and signal refreshes without importing routes.
/// Only complete, valid UPDATEs and KEEPALIVEs reset the negotiated hold timer.
async fn receive(
    reader: &mut (impl AsyncRead + Unpin),
    n: &Negotiated,
    refresh: &Refresh,
) -> Result<()> {
    let mut expires = Instant::now() + Duration::from_secs(n.hold as u64);
    loop {
        let packet = if n.hold == 0 {
            wire::read_frame(reader).await?
        } else {
            match tokio::time::timeout_at(expires, wire::read_frame(reader)).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(ProtocolError {
                        code: 4,
                        subcode: 0,
                        data: vec![],
                        reason: "hold timer expired",
                    }
                    .into());
                }
            }
        };
        match packet.0 {
            wire::KEEPALIVE => expires = Instant::now() + Duration::from_secs(n.hold as u64),
            wire::UPDATE => {
                let action = wire::validate_update(&packet.1, n)?;
                if action != wire::UpdateAction::Valid {
                    warn!(?action, prefixes = ?wire::update_prefixes(&packet.1),
                        packet = ?wire::frame(wire::UPDATE, &packet.1),
                        "recovered inbound UPDATE; no received routes are installed");
                }
                expires = Instant::now() + Duration::from_secs(n.hold as u64);
            }
            wire::ROUTE_REFRESH => {
                if let Some(v6) = wire::refresh_family(&packet.1, n)? {
                    refresh.request(v6);
                }
            }
            other => return Err(wire::unexpected(other, &packet.1)),
        }
        // An inbound route flood cannot monopolize a runtime worker.
        tokio::task::yield_now().await;
    }
}

struct Plan {
    withdrawals: VecDeque<IpNet>,
    additions: VecDeque<IpNet>,
}
impl Plan {
    /// Diff against sent routes, gate additions by negotiated family, and replay on refresh.
    fn new(advertised: &Prefixes, desired: &Prefixes, n: &Negotiated, replay: &Prefixes) -> Self {
        let enabled = |p: &IpNet| if p.addr().is_ipv4() { n.ipv4 } else { n.ipv6 };
        let mut plan = Self {
            withdrawals: advertised
                .iter()
                .filter(|p| !desired.contains(p) || !enabled(p))
                .copied()
                .collect(),
            additions: desired
                .iter()
                .filter(|p| enabled(p) && (replay.contains(p) || !advertised.contains(p)))
                .copied()
                .collect(),
        };
        // Keep each family contiguous so dual-stack exports use full batches.
        plan.withdrawals
            .make_contiguous()
            .sort_unstable_by_key(|p| p.addr().is_ipv6());
        plan.additions
            .make_contiguous()
            .sort_unstable_by_key(|p| p.addr().is_ipv6());
        plan
    }
    /// Take a bounded batch of one address family, draining withdrawals before additions.
    /// The returned flag is true for withdrawals.
    fn next(&mut self) -> Option<(bool, Vec<IpNet>)> {
        let withdraw = !self.withdrawals.is_empty();
        let queue = if withdraw {
            &mut self.withdrawals
        } else {
            &mut self.additions
        };
        let v6 = queue.front()?.addr().is_ipv6();
        let mut batch = Vec::with_capacity(wire::MAX_UPDATE_PREFIXES);
        while batch.len() < wire::MAX_UPDATE_PREFIXES
            && queue.front().is_some_and(|p| p.addr().is_ipv6() == v6)
        {
            batch.push(queue.pop_front().unwrap());
        }
        Some((withdraw, batch))
    }
}
/// Mark the latest snapshot seen and select the ACL's exports, defaulting to empty.
fn desired(rx: &mut watch::Receiver<Arc<Exports>>, acl: &str) -> Arc<Prefixes> {
    rx.borrow_and_update().get(acl).cloned().unwrap_or_default()
}

/// Send export changes, refresh replays, end-of-RIB markers, and timed KEEPALIVEs.
/// Replan from successfully written routes when snapshots change during transmission.
async fn transmit(
    writer: &mut (impl AsyncWrite + Unpin),
    cfg: &Config,
    p: &Peer,
    n: &Negotiated,
    mut exports: watch::Receiver<Arc<Exports>>,
    refresh: &Refresh,
) -> Result<()> {
    let mut advertised = Prefixes::new();
    let mut target = desired(&mut exports, &p.export_acl);
    let mut replay = Prefixes::new();
    let mut plan = Plan::new(&advertised, &target, n, &replay);
    let keepalive = Duration::from_secs((n.hold as u64 / 3).max(1));
    let mut next_keepalive = Instant::now() + keepalive;
    let mut eor = u8::from(n.ipv4) | (u8::from(n.ipv6) << 1);
    let mut last_replan = Instant::now();
    let mut next_refresh = Instant::now();
    loop {
        // Replan against what was actually written, never against an obsolete
        // queued snapshot. Coalesce rapid snapshots without starving transmission.
        if exports.has_changed()? && last_replan.elapsed() >= Duration::from_millis(100) {
            target = desired(&mut exports, &p.export_acl);
            replay.retain(|prefix| target.contains(prefix));
            plan = Plan::new(&advertised, &target, n, &replay);
            last_replan = Instant::now();
        }
        if eor == 0 && Instant::now() >= next_refresh {
            let families = refresh.pending.swap(0, Ordering::Relaxed);
            if families != 0 {
                replay = target
                    .iter()
                    .filter(|prefix| families & if prefix.addr().is_ipv6() { 2 } else { 1 } != 0)
                    .copied()
                    .collect();
                plan = Plan::new(&advertised, &target, n, &replay);
                eor = families & (u8::from(n.ipv4) | (u8::from(n.ipv6) << 1));
                next_refresh = Instant::now() + Duration::from_secs(1);
            }
        }
        if n.hold != 0 && Instant::now() >= next_keepalive {
            send(
                writer,
                &wire::frame(wire::KEEPALIVE, &[]),
                p.write_timeout_secs,
            )
            .await?;
            next_keepalive = Instant::now() + keepalive;
        }
        if let Some((withdraw, batch)) = plan.next() {
            send(
                writer,
                &wire::update(cfg, p, n, &batch, withdraw),
                p.write_timeout_secs,
            )
            .await?;
            for prefix in batch {
                replay.remove(&prefix);
                if withdraw {
                    advertised.remove(&prefix);
                } else {
                    advertised.insert(prefix);
                }
            }
            tokio::task::yield_now().await;
            continue;
        }
        if eor != 0 {
            if eor & 1 != 0 {
                send(writer, &wire::end_of_rib(false), p.write_timeout_secs).await?;
            }
            if eor & 2 != 0 {
                send(writer, &wire::end_of_rib(true), p.write_timeout_secs).await?;
            }
            eor = 0;
            debug!(peer = %p.address, prefixes = advertised.len(), "BGP export synchronized");
        }
        tokio::select! {
            result = exports.changed() => {
                result?;
                target = desired(&mut exports,&p.export_acl);
                replay.retain(|prefix| target.contains(prefix));
                plan = Plan::new(&advertised,&target,n,&replay);
                last_replan = Instant::now();
            }
            _ = refresh.ready.notified() => {}
            _ = sleep_until(next_refresh), if eor == 0 && refresh.pending.load(Ordering::Relaxed) != 0 => {}
            _ = sleep_until(next_keepalive), if n.hold != 0 => {}
        }
    }
}

/// Confirm the OPEN candidate, then drive receive and transmit until either stops.
/// Fill an omitted link-local next hop from the interface and expose session status.
async fn session(
    status: Status,
    mut candidate: Candidate,
    cfg: Arc<Config>,
    mut p: Peer,
    exports: watch::Receiver<Arc<Exports>>,
) -> Result<()> {
    if p.ipv6 && p.next_hop_v6_link_local.is_none() {
        p.next_hop_v6_link_local = candidate.link_local;
    }
    management::update(&status, "OpenConfirm", None);
    let n = candidate.negotiated;
    send(
        &mut candidate.stream,
        &wire::frame(wire::KEEPALIVE, &[]),
        p.write_timeout_secs,
    )
    .await?;
    let confirm_secs = if n.hold == 0 {
        p.connect_timeout_secs
    } else {
        n.hold as u64
    };
    info!(peer = %p.address, incoming = candidate.incoming, "BGP OpenConfirm: waiting for KEEPALIVE");
    let confirm = timeout(
        Duration::from_secs(confirm_secs),
        wire::read_frame(&mut candidate.stream),
    )
    .await;
    let (kind, body) = match confirm {
        Ok(Ok(packet)) => packet,
        result => {
            let e = match result {
                Ok(Err(error)) => error,
                _ => ProtocolError {
                    code: if n.hold == 0 { 5 } else { 4 },
                    subcode: 0,
                    data: vec![],
                    reason: "OpenConfirm timeout",
                }
                .into(),
            };
            report(&mut candidate.stream, &e).await;
            return Err(e);
        }
    };
    if kind != wire::KEEPALIVE {
        let e = wire::unexpected(kind, &body);
        report(&mut candidate.stream, &e).await;
        return Err(e);
    }
    management::update(&status, "Established", None);
    info!(peer = %p.address, remote_id = %n.router_id, incoming = candidate.incoming, hold = n.hold, ipv4 = n.ipv4, ipv6 = n.ipv6, "BGP Established");
    let (mut reader, mut writer) = candidate.stream.into_split();
    let refresh = Refresh::default();
    // Reader and writer advance independently: a blocked write never stops the
    // receive hold timer. Cancellation closes the session, so partial frames
    // are never resumed on a different stream.
    let result = tokio::select! {
        result = receive(&mut reader,&n,&refresh) => result,
        result = transmit(&mut writer,&cfg,&p,&n,exports,&refresh) => result,
    };
    if let Err(ref e) = result {
        report(&mut writer, e).await;
    }
    management::update(
        &status,
        "Active",
        result.as_ref().err().map(|e| format!("{e:#}")),
    );
    result
}

/// Maintain one peer session with bounded outbound backoff and incoming acceptance.
async fn peer_loop(
    status: Status,
    cfg: Arc<Config>,
    p: Peer,
    mut incoming: mpsc::Receiver<TcpStream>,
    exports: watch::Receiver<Arc<Exports>>,
) -> Result<()> {
    let mut failures = 0u32;
    loop {
        management::update(&status, "Connect", None);
        match choose(cfg.clone(), p.clone(), &mut incoming).await {
            Ok(candidate) => {
                let started = Instant::now();
                let session = session(
                    status.clone(),
                    candidate,
                    cfg.clone(),
                    p.clone(),
                    exports.clone(),
                );
                tokio::pin!(session);
                loop {
                    tokio::select! {
                        result = &mut session => {
                            if let Err(e) = result { management::update(&status, "Active", Some(format!("{e:#}"))); warn!(peer = %p.address, e = %format!("{e:#}"), "BGP session closed"); }
                            break;
                        }
                        stream = incoming.recv() => {
                            let Some(stream) = stream else { bail!("listener stopped"); };
                            // An established session wins over new connections.
                            // Closing a redundant connection cannot block this peer.
                            let _ = stream.try_write(&wire::notification(6,7,&[]));
                        }
                    }
                }
                if started.elapsed() >= Duration::from_secs(30) {
                    failures = 0;
                }
            }
            Err(e) => {
                management::update(&status, "Active", Some(format!("{e:#}")));
                warn!(peer = %p.address, local = %p.local_address, interface = %p.interface, port = p.port, md5 = p.md5_password.is_some(), e = %format!("{e:#}"), "BGP connection failed")
            }
        }
        management::update(&status, "Active", None);
        failures = failures.saturating_add(1);
        let base = (1u64 << failures.min(5)).min(30);
        let jitter = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis() as u64;
        info!(peer = %p.address, retry_ms = base * 1000 + jitter, "BGP Active: waiting before outgoing retry; accepting incoming connections");
        // Still accept incoming sessions during outbound backoff.
        tokio::select! {
            _ = sleep(Duration::from_millis(base * 1000 + jitter)) => {}
            stream = incoming.recv() => {
                let Some(stream) = stream else { bail!("listener stopped"); };
                match handshake(stream,cfg.clone(),p.clone(),true).await {
                    Ok(candidate) => {
                        if let Err(e) = session(status.clone(),candidate,cfg.clone(),p.clone(),exports.clone()).await { management::update(&status, "Active", Some(format!("{e:#}"))); warn!(peer = %p.address, e = %format!("{e:#}"), "incoming BGP session closed"); }
                    }
                    Err(e) => {
                        management::update(&status, "Active", Some(format!("{e:#}")));
                        warn!(peer = %p.address, e = %format!("{e:#}"), "incoming handshake failed");
                    },
                }
            }
        }
    }
}

/// Run peer workers and shared listeners, dispatching only configured remote addresses.
/// `statuses` must correspond to `cfg.peers` in order; any worker exit ends this task.
pub async fn run(
    cfg: Arc<Config>,
    exports: watch::Receiver<Arc<Exports>>,
    statuses: Vec<Status>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    type ListenerPeers = HashMap<IpAddr, mpsc::Sender<TcpStream>>;
    let mut listeners: HashMap<(IpAddr, String), ListenerPeers> = HashMap::new();
    for (p, status) in cfg.peers.iter().zip(statuses) {
        let (tx, rx) = mpsc::channel(2);
        listeners
            .entry((p.local_address, p.interface.clone()))
            .or_default()
            .insert(p.address, tx);
        tasks.spawn(peer_loop(
            status,
            cfg.clone(),
            p.clone(),
            rx,
            exports.clone(),
        ));
    }
    for ((local, interface), peers) in listeners {
        let p = cfg
            .peers
            .iter()
            .find(|p| p.local_address == local && p.interface == interface)
            .unwrap();
        let idx = index(p)?;
        let socket = Socket::new(
            if local.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            },
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        socket.set_reuse_address(true)?;
        if local.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        configure(&SockRef::from(&socket), p)?;
        // Multiple neighbors share this listener. Install every configured key
        // before accepting SYNs; applying only the first peer's key is unsafe.
        for peer in cfg
            .peers
            .iter()
            .filter(|peer| peer.local_address == local && peer.interface == interface)
        {
            crate::tcp_md5::install(&socket, peer, idx)?;
        }
        socket.set_nonblocking(true)?;
        socket
            .bind(&endpoint(local, cfg.listen_port, idx).into())
            .with_context(|| format!("binding {local}:{} on {interface}", cfg.listen_port))?;
        socket.listen(64)?;
        let listener = TcpListener::from_std(socket.into())?;
        info!(%local, %interface, port = cfg.listen_port, "listening for configured BGP peers");
        tasks.spawn(async move {
            loop {
                let (stream, remote) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(error) => return Err(error.into()),
                };
                if let Some(tx) = peers.get(&remote.ip()) {
                    let _ = tx.try_send(stream);
                }
                // Unconfigured sources and full per-peer queues are simply closed.
            }
        });
    }
    tasks.join_next().await.context("no BGP tasks")??
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn selection_preserves_outgoing_failure_when_no_peer_connects() {
        let cfg: Config = toml::from_str(include_str!("../examples/ubgp.toml")).unwrap();
        let mut peer = cfg.peers[0].clone();
        peer.interface = "ubgp-missing".into();
        peer.connect_timeout_secs = 0;
        let (_sender, mut receiver) = mpsc::channel(1);
        let error = choose(Arc::new(cfg), peer, &mut receiver)
            .await
            .err()
            .unwrap();
        let message = format!("{error:#}");
        assert!(message.contains("outgoing TCP setup"), "{message}");
        assert!(
            message.contains("interface ubgp-missing does not exist"),
            "{message}"
        );
        assert!(
            message.contains("no incoming TCP connection received"),
            "{message}"
        );
    }
    fn n() -> Negotiated {
        Negotiated {
            router_id: "192.0.2.2".parse().unwrap(),
            hold: 3,
            asn4: true,
            internal: false,
            ipv4: true,
            ipv6: false,
        }
    }
    #[test]
    fn changing_snapshot_preserves_withdrawals_and_family_gate() {
        let advertised: Prefixes = ["10.0.0.0/24", "10.1.0.0/24"]
            .map(|s| s.parse().unwrap())
            .into_iter()
            .collect();
        let desired: Prefixes = ["10.1.0.0/24", "10.2.0.0/24", "2001:db8::/32"]
            .map(|s| s.parse().unwrap())
            .into_iter()
            .collect();
        let mut plan = Plan::new(&advertised, &desired, &n(), &Prefixes::new());
        assert_eq!(
            plan.next(),
            Some((true, vec!["10.0.0.0/24".parse().unwrap()]))
        );
        assert_eq!(
            plan.next(),
            Some((false, vec!["10.2.0.0/24".parse().unwrap()]))
        );
        assert_eq!(plan.next(), None);
        let refresh = Plan::new(&advertised, &desired, &n(), &desired);
        assert_eq!(refresh.withdrawals.len(), 1);
        assert_eq!(refresh.additions.len(), 2);
    }
    #[tokio::test]
    async fn slow_writer_has_a_deadline() {
        let (mut writer, _reader) = tokio::io::duplex(64);
        let error = send(&mut writer, &[0; 4096], 1).await.unwrap_err();
        assert!(error.to_string().contains("write deadline"));
    }
    #[tokio::test]
    async fn hold_timer_expires_with_partial_frame() {
        let (_writer, mut reader) = tokio::io::duplex(64);
        let e = receive(&mut reader, &n(), &Refresh::default())
            .await
            .unwrap_err();
        assert_eq!(e.downcast_ref::<ProtocolError>().unwrap().code, 4);
    }
    #[tokio::test]
    async fn writer_sends_initial_routes_and_later_withdrawal() {
        let c: Config = toml::from_str(include_str!("../examples/ubgp.toml")).unwrap();
        let p = c.peers[0].clone();
        let acl = p.export_acl.clone();
        let initial: Prefixes = ["198.51.100.0/24".parse().unwrap()].into_iter().collect();
        let (tx, rx) = watch::channel(Arc::new(HashMap::from([(acl, Arc::new(initial))])));
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            transmit(&mut writer, &c, &p, &n(), rx, &Refresh::default()).await
        });
        let (kind, body) = wire::read_frame(&mut reader).await.unwrap();
        assert_eq!(kind, 2);
        assert_eq!(&body[..2], &[0, 0]);
        let (_, eor) = wire::read_frame(&mut reader).await.unwrap();
        assert_eq!(eor, vec![0, 0, 0, 0]);
        tx.send_replace(Arc::new(HashMap::new()));
        let (_, body) = wire::read_frame(&mut reader).await.unwrap();
        assert_eq!(&body[..2], &[0, 4]);
        task.abort();
    }
    #[tokio::test]
    async fn recoverable_update_does_not_stop_receive_loop() {
        // Missing mandatory attributes: treat the advertised route as withdrawn.
        let mut input = wire::frame(wire::UPDATE, &[0, 0, 0, 0, 24, 10, 1, 0]);
        input.extend(wire::frame(wire::KEEPALIVE, &[]));
        input.extend(wire::notification(6, 0, &[]));
        let error = receive(&mut input.as_slice(), &n(), &Refresh::default())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("peer sent NOTIFICATION code=6"),
            "{error:#}"
        );
    }
    /// Read a complete family export and return the reachable prefixes it carried.
    async fn exported(reader: &mut (impl AsyncRead + Unpin), v6: bool) -> Prefixes {
        let mut prefixes = Prefixes::new();
        loop {
            let (kind, body) = timeout(Duration::from_secs(5), wire::read_frame(reader))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(kind, wire::UPDATE);
            if body == wire::end_of_rib(v6)[19..] {
                return prefixes;
            }
            prefixes.extend(wire::update_prefixes(&body));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_during_cooldown_is_delayed_and_replayed() {
        let c: Config = toml::from_str(include_str!("../examples/ubgp.toml")).unwrap();
        let p = c.peers[0].clone();
        let prefixes: Prefixes = ["10.1.0.0/24".parse().unwrap()].into_iter().collect();
        let (_tx, rx) = watch::channel(Arc::new(Exports::from([(
            p.export_acl.clone(),
            Arc::new(prefixes.clone()),
        )])));
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let refresh = Arc::new(Refresh::default());
        let sender = refresh.clone();
        let task = tokio::spawn(async move {
            let mut negotiated = n();
            negotiated.hold = 0;
            transmit(&mut writer, &c, &p, &negotiated, rx, &sender).await
        });
        assert_eq!(exported(&mut reader, false).await, prefixes);
        refresh.request(false);
        assert_eq!(exported(&mut reader, false).await, prefixes);
        let first = Instant::now();
        refresh.request(false);
        refresh.request(false); // Repeated requests coalesce into one pending replay.
        assert_eq!(exported(&mut reader, false).await, prefixes);
        assert!(first.elapsed() >= Duration::from_secs(1));
        assert!(
            timeout(Duration::from_secs(2), wire::read_frame(&mut reader))
                .await
                .is_err()
        );
        task.abort();
        let _ = task.await;
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_replays_only_requested_family() {
        let c: Config = toml::from_str(include_str!("../examples/ubgp.toml")).unwrap();
        let mut p = c.peers[0].clone();
        p.next_hop_v6 = Some("2001:db8::1".parse().unwrap());
        let prefixes: Prefixes = ["10.1.0.0/24", "2001:db8::/32"]
            .map(|s| s.parse().unwrap())
            .into_iter()
            .collect();
        let (_tx, rx) = watch::channel(Arc::new(Exports::from([(
            p.export_acl.clone(),
            Arc::new(prefixes),
        )])));
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let refresh = Arc::new(Refresh::default());
        let sender = refresh.clone();
        let task = tokio::spawn(async move {
            let mut negotiated = n();
            negotiated.hold = 0;
            negotiated.ipv6 = true;
            transmit(&mut writer, &c, &p, &negotiated, rx, &sender).await
        });
        exported(&mut reader, true).await;
        // Exercise the receive loop's family dispatch as well as transmission.
        let mut negotiated = n();
        negotiated.ipv6 = true;
        let mut input = wire::frame(wire::ROUTE_REFRESH, &[0, 2, 0, 1]);
        input.extend(wire::notification(6, 0, &[]));
        assert!(
            receive(&mut input.as_slice(), &negotiated, &refresh)
                .await
                .unwrap_err()
                .to_string()
                .contains("peer sent NOTIFICATION")
        );
        assert_eq!(
            exported(&mut reader, true).await,
            ["2001:db8::/32".parse().unwrap()].into_iter().collect()
        );
        assert!(
            timeout(Duration::from_secs(2), wire::read_frame(&mut reader))
                .await
                .is_err()
        );
        task.abort();
        let _ = task.await;
    }

    #[tokio::test(start_paused = true)]
    async fn snapshot_change_preserves_unfinished_refresh() {
        let c: Config = toml::from_str(include_str!("../examples/ubgp.toml")).unwrap();
        let p = c.peers[0].clone();
        let acl = p.export_acl.clone();
        let mut prefixes: Prefixes = (0..600u32)
            .map(|i| IpNet::new(std::net::Ipv4Addr::from(0x0a000000 + i).into(), 32).unwrap())
            .collect();
        let (tx, rx) = watch::channel(Arc::new(Exports::from([(
            acl.clone(),
            Arc::new(prefixes.clone()),
        )])));
        // Backpressure keeps multiple replay batches outstanding when the snapshot changes.
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let refresh = Arc::new(Refresh::default());
        let sender = refresh.clone();
        let task = tokio::spawn(async move {
            let mut negotiated = n();
            negotiated.hold = 0;
            transmit(&mut writer, &c, &p, &negotiated, rx, &sender).await
        });
        assert_eq!(exported(&mut reader, false).await, prefixes);
        refresh.request(false);
        let (_, first) = wire::read_frame(&mut reader).await.unwrap();
        let mut replayed: Prefixes = wire::update_prefixes(&first).into_iter().collect();
        assert_eq!(replayed.len(), wire::MAX_UPDATE_PREFIXES);
        prefixes.insert("10.99.0.1/32".parse().unwrap());
        tx.send_replace(Arc::new(Exports::from([(acl, Arc::new(prefixes.clone()))])));
        tokio::time::advance(Duration::from_millis(150)).await;
        replayed.extend(exported(&mut reader, false).await);
        assert_eq!(replayed, prefixes);
        task.abort();
        let _ = task.await;
    }
}
