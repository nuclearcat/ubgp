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
use ubgp::{bgp, config::Config, management, netlink};

mod cli;
mod daemon;

/// Validate startup arguments and configuration, then detach before creating threads.
fn main() -> Result<()> {
    let (path, background, debug, check) = match cli::parse(std::env::args_os().skip(1))? {
        cli::Command::Help => {
            println!("{}", cli::HELP);
            return Ok(());
        }
        cli::Command::Version => {
            println!("ubgp {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        cli::Command::Run {
            path,
            daemon,
            debug,
            check,
        } => (path, daemon, debug, check),
    };
    // Preserve relative config paths across daemon() changing cwd; retaining
    // symlinks allows operators to replace a configuration symlink on reload.
    let path = std::path::absolute(path).context("resolving configuration path")?;
    let config = Config::load(&path)?;
    if check {
        println!("{}: configuration valid", path.display());
        return Ok(());
    }
    // Fork before creating any runtime threads or logging locks.
    if background {
        daemon::detach()?;
    }
    daemon::init_logging(background, debug);
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating Tokio runtime")
        .and_then(|runtime| runtime.block_on(run(path, config)));
    if let Err(ref error) = result {
        tracing::error!(error = %format!("{error:#}"), "ubgp failed");
    }
    result
}

/// Supervise kernel, BGP, and console workers until shutdown or a fatal worker exit.
/// SIGHUP restarts workers with validated configuration; invalid reloads keep the old one.
async fn run(path: PathBuf, mut config: Config) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut hup = signal(SignalKind::hangup())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    loop {
        let cfg = Arc::new(config.clone());
        let listener = management::bind(&cfg).await?;
        let statuses = management::statuses(&cfg);
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = watch::channel(Arc::new(netlink::Exports::new()));
        let c = cfg.clone();
        let s = stop.clone();
        let mut kernel = tokio::task::spawn_blocking(move || netlink::run(c, tx, s));
        let mut console = tokio::spawn(management::run(
            listener,
            cfg.clone(),
            statuses.clone(),
            rx.clone(),
        ));
        let mut bgp = tokio::spawn(bgp::run(cfg, rx, statuses));
        info!(config = %path.display(), "ubgp started");
        let replacement = loop {
            tokio::select! {
                result = &mut kernel => {
                    console.abort(); let _ = (&mut console).await;
                    stop.store(true,Ordering::Relaxed); bgp.abort(); let _ = bgp.await;
                    result.context("netlink worker panicked")??;
                    bail!("netlink worker stopped unexpectedly");
                }
                result = &mut bgp => {
                    console.abort(); let _ = (&mut console).await;
                    stop.store(true,Ordering::Relaxed); let _ = kernel.await;
                    result.context("BGP task panicked")??;
                    bail!("BGP task stopped unexpectedly");
                }
                result = &mut console => {
                    stop.store(true, Ordering::Relaxed); bgp.abort(); let _ = bgp.await; let _ = kernel.await;
                    result.context("management task panicked")??;
                    bail!("management task stopped unexpectedly");
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
        console.abort();
        let _ = console.await;
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
