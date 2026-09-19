//! Bounded, read-only, loopback management console with minimal Telnet support.
use crate::{config::Config, netlink::Exports};
use anyhow::{Context, Result, bail};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
    time::timeout,
};

pub struct PeerStatus {
    pub state: &'static str,
    pub since: Instant,
    pub last_error: Option<String>,
}
pub type Status = Arc<Mutex<PeerStatus>>;
/// Create shared Idle status records in configuration peer order.
pub fn statuses(cfg: &Config) -> Vec<Status> {
    cfg.peers
        .iter()
        .map(|_| {
            Arc::new(Mutex::new(PeerStatus {
                state: "Idle",
                since: Instant::now(),
                last_error: None,
            }))
        })
        .collect()
}
/// Set the state and reset its age, preserving the last error when none is supplied.
pub fn update(status: &Status, state: &'static str, error: Option<String>) {
    let mut status = status.lock().unwrap();
    status.state = state;
    status.since = Instant::now();
    if let Some(error) = error {
        status.last_error = Some(error);
    }
}

/// Bind the validated management address, or return `None` when disabled.
pub async fn bind(cfg: &Config) -> Result<Option<TcpListener>> {
    if !cfg.management.enabled {
        return Ok(None);
    }
    let listener = TcpListener::bind(cfg.management.listen)
        .await
        .context("binding management CLI")?;
    tracing::info!(address = %cfg.management.listen, "management CLI listening");
    Ok(Some(listener))
}

/// Serve at most 16 loopback clients, isolating individual console failures.
/// With no listener, remain pending until the supervisor cancels this task.
pub async fn run(
    listener: Option<TcpListener>,
    cfg: Arc<Config>,
    statuses: Vec<Status>,
    exports: watch::Receiver<Arc<Exports>>,
) -> Result<()> {
    let Some(listener) = listener else {
        return std::future::pending().await;
    };
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, address) = accepted?;
                if !address.ip().is_loopback() || clients.len() >= 16 { continue; }
                let cfg = cfg.clone();
                let statuses = statuses.clone();
                let exports = exports.clone();
                clients.spawn(async move { let _ = console(stream, cfg, statuses, exports).await; });
            }
            _ = clients.join_next(), if !clients.is_empty() => {}
        }
    }
}

/// Write a complete console response with a five-second deadline.
async fn write(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    timeout(Duration::from_secs(5), stream.write_all(bytes))
        .await
        .context("CLI write timeout")??;
    Ok(())
}
/// Replace non-ASCII and control characters with `?` for terminal-safe output.
/// Use for peer-supplied/error text; never render configuration Debug output.
fn safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() {
                c
            } else {
                '?'
            }
        })
        .collect()
}
const HELP: &str = "help                       Show commands\r\nshow summary               Router and session summary\r\nshow peers                 Peer state, state age and last error\r\nshow routes ACL [PREFIX]    ACL export candidates (maximum 100; not advertised RIB)\r\nquit / exit                Close console\r\n";

/// Handle one read-only console with input deadlines and bounded route listings.
/// Route output reflects ACL candidates, not confirmed peer advertisements.
async fn console(
    mut stream: TcpStream,
    cfg: Arc<Config>,
    statuses: Vec<Status>,
    exports: watch::Receiver<Arc<Exports>>,
) -> Result<()> {
    write(
        &mut stream,
        b"ubgp read-only management CLI\r\nType help for commands.\r\nubgp> ",
    )
    .await?;
    let mut skip_lf = false;
    loop {
        let Some(line) = timeout(Duration::from_secs(300), line(&mut stream, &mut skip_lf))
            .await
            .context("CLI input timeout")??
        else {
            return Ok(());
        };
        let args: Vec<_> = line.split_whitespace().collect();
        match args.as_slice() {
            ["quit" | "exit"] => {
                write(&mut stream, b"Bye\r\n").await?;
                return Ok(());
            }
            [] => {}
            ["help" | "?"] => write(&mut stream, HELP.as_bytes()).await?,
            ["show", "summary"] => {
                let established = statuses
                    .iter()
                    .filter(|s| s.lock().unwrap().state == "Established")
                    .count();
                let text = format!(
                    "Router ID {}  AS {}  IPv6 {}\r\nPeers {}  Established {}\r\nSelected tables {:?}\r\nACLs: {}\r\n",
                    cfg.router_id,
                    cfg.asn,
                    cfg.ipv6,
                    cfg.peers.len(),
                    established,
                    cfg.kernel.tables,
                    cfg.acls.len()
                );
                write(&mut stream, text.as_bytes()).await?;
                let snapshot = exports.borrow().clone();
                for name in cfg.acls.keys() {
                    let count = snapshot.get(name).map_or(0, |r| r.len());
                    write(
                        &mut stream,
                        format!("  {}: {} export candidates\r\n", safe(name), count).as_bytes(),
                    )
                    .await?;
                }
            }
            ["show", "peers"] => {
                write(
                    &mut stream,
                    b"Peer / interface  Remote-AS  State  Age(s)  MD5  Last error\r\n",
                )
                .await?;
                for (peer, status) in cfg.peers.iter().zip(&statuses) {
                    let text = {
                        let status = status.lock().unwrap();
                        format!(
                            "{} / {}  {}  {}  {}  {}  {}\r\n",
                            peer.address,
                            safe(&peer.interface),
                            peer.remote_asn,
                            status.state,
                            status.since.elapsed().as_secs(),
                            peer.md5_password.is_some(),
                            safe(status.last_error.as_deref().unwrap_or("-"))
                        )
                    };
                    write(&mut stream, text.as_bytes()).await?;
                }
            }
            ["show", "routes", acl, rest @ ..] if rest.len() <= 1 => {
                let filter = if let Some(prefix) = rest.first() {
                    match prefix.parse::<ipnet::IpNet>() {
                        Ok(prefix) => Some(prefix),
                        Err(_) => {
                            write(&mut stream, b"Invalid prefix\r\nubgp> ").await?;
                            continue;
                        }
                    }
                } else {
                    None
                };
                let snapshot = exports.borrow().clone();
                if !cfg.acls.contains_key(*acl) {
                    write(&mut stream, b"Unknown ACL; use show summary\r\n").await?;
                } else if let Some(routes) = snapshot.get(*acl) {
                    write(
                        &mut stream,
                        b"ACL export candidates; not confirmation of peer advertisement.\r\n",
                    )
                    .await?;
                    let selected: Vec<_> = match filter {
                        Some(prefix) => routes.get(&prefix).copied().into_iter().collect(),
                        None => routes.iter().take(100).copied().collect(),
                    };
                    for route in &selected {
                        write(&mut stream, format!("{route}\r\n").as_bytes()).await?;
                    }
                    write(
                        &mut stream,
                        format!(
                            "Shown {}; ACL total {} (unordered, limit 100)\r\n",
                            selected.len(),
                            routes.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                } else {
                    write(&mut stream, b"No export candidates available\r\n").await?;
                }
            }
            _ => write(&mut stream, b"Unknown command; type help\r\n").await?,
        }
        write(&mut stream, b"ubgp> ").await?;
    }
}

/// Read an ASCII command while refusing Telnet options and processing backspaces.
/// Preserve CR-LF/CR-NUL handling across calls via `skip_lf`; return `None` at EOF.
/// Reject commands over 512 bytes or input exceeding 8192 wire bytes per call.
async fn line(stream: &mut TcpStream, skip_lf: &mut bool) -> Result<Option<String>> {
    let mut bytes = Vec::new();
    let mut state = 0;
    let mut option_command = 0;
    let mut wire_bytes = 0;
    loop {
        let mut byte = [0];
        if stream.read(&mut byte).await? == 0 {
            return Ok(None);
        }
        let b = byte[0];
        if *skip_lf {
            *skip_lf = false;
            if b == b'\n' || b == 0 {
                continue;
            }
        }
        wire_bytes += 1;
        if wire_bytes > 8192 {
            bail!("CLI input limit exceeded");
        }
        match state {
            1 => match b {
                251..=254 => {
                    option_command = b;
                    state = 2;
                }
                250 => state = 3,
                _ => state = 0,
            },
            2 => {
                // Refuse WILL/DO once; do not answer refusals (avoids loops).
                if option_command == 251 {
                    write(stream, &[255, 254, b]).await?;
                }
                if option_command == 253 {
                    write(stream, &[255, 252, b]).await?;
                }
                state = 0;
            }
            3 => {
                if b == 255 {
                    state = 4;
                }
            }
            4 => {
                state = if b == 240 { 0 } else { 3 };
            }
            _ => match b {
                255 => state = 1,
                b'\n' => return Ok(Some(String::from_utf8(bytes)?)),
                b'\r' => {
                    *skip_lf = true;
                    return Ok(Some(String::from_utf8(bytes)?));
                }
                0 => {}
                8 | 127 => {
                    bytes.pop();
                }
                32..=126 | b'\t' => {
                    bytes.push(b);
                    if bytes.len() > 512 {
                        bail!("CLI command too long");
                    }
                }
                _ => {}
            },
        }
    }
}
