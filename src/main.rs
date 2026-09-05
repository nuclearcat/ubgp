use anyhow::{Context, Result, bail};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::watch;
use tracing::{info, warn};
use ubgp::{bgp, config::Config, netlink};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ubgp=info".into()),
        )
        .init();
    let mut path = PathBuf::from("/etc/ubgp.toml");
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => path = args.next().context("--config requires a path")?.into(),
            "--check-config" => check = true,
            "--help" | "-h" => {
                println!(
                    "ubgp [--config PATH] [--check-config]\nDefault config: /etc/ubgp.toml\nSIGHUP: validate and reload configuration (reconnects peers).\nSIGTERM/SIGINT: close sessions and stop."
                );
                return Ok(());
            }
            "--version" | "-V" => {
                println!("ubgp {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ => bail!("unknown argument: {arg}"),
        }
    }
    let mut config = Config::load(&path)?;
    if check {
        println!("{}: configuration valid", path.display());
        return Ok(());
    }
    use tokio::signal::unix::{SignalKind, signal};
    let mut hup = signal(SignalKind::hangup())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    loop {
        let cfg = Arc::new(config.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = watch::channel(Arc::new(netlink::Exports::new()));
        let c = cfg.clone();
        let s = stop.clone();
        let mut kernel = tokio::task::spawn_blocking(move || netlink::run(c, tx, s));
        let mut bgp = tokio::spawn(bgp::run(cfg, rx));
        info!(config = %path.display(), "ubgp started");
        let replacement = loop {
            tokio::select! {
                result = &mut kernel => {
                    stop.store(true,Ordering::Relaxed); bgp.abort(); let _ = bgp.await;
                    result.context("netlink worker panicked")??;
                    bail!("netlink worker stopped unexpectedly");
                }
                result = &mut bgp => {
                    stop.store(true,Ordering::Relaxed); let _ = kernel.await;
                    result.context("BGP task panicked")??;
                    bail!("BGP task stopped unexpectedly");
                }
                _ = hup.recv() => match Config::load(&path) {
                    Ok(next) => { info!("configuration validated; restarting sessions with new policy"); break Some(next); }
                    Err(e) => warn!(%e, "reload rejected; keeping running configuration"),
                },
                _ = term.recv() => break None,
                _ = interrupt.recv() => break None,
            }
        };
        stop.store(true, Ordering::Relaxed);
        // We do not advertise Graceful Restart: closing TCP withdraws the old
        // session's routes at the neighbor, including on policy reload.
        bgp.abort();
        let _ = bgp.await;
        kernel.await.context("joining netlink worker")??;
        match replacement {
            Some(next) => config = next,
            None => {
                info!("ubgp stopped");
                return Ok(());
            }
        }
    }
}
