use anyhow::{Result, bail, ensure};
use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
};

pub const HELP: &str = "Usage: ubgp [OPTIONS]

  -c, --config PATH   Configuration file (default: /etc/ubgp.toml)
  -d, --daemon        Detach into the background; log to syslog
      --debug        Enable verbose diagnostic logs (overrides RUST_LOG)
      --check-config Validate configuration and exit without starting
  -h, --help         Print help
  -V, --version      Print version

--config=PATH is also accepted. Foreground operation is the default.
SIGHUP reloads configuration; SIGTERM/SIGINT stops the daemon.";

#[derive(Debug, PartialEq)]
pub enum Command {
    Help,
    Version,
    Run {
        path: PathBuf,
        daemon: bool,
        debug: bool,
        check: bool,
    },
}

/// Parse arguments after the executable name, preserving non-UTF-8 config paths.
/// Reject unknown options and missing values; help and version return immediately.
///
/// # Errors
/// Returns an error for an unknown argument or an absent/empty configuration path.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command> {
    let mut path = PathBuf::from("/etc/ubgp.toml");
    let mut daemon = false;
    let mut debug = false;
    let mut check = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--help" | "-h") => return Ok(Command::Help),
            Some("--version" | "-V") => return Ok(Command::Version),
            Some("--daemon" | "-d") => daemon = true,
            Some("--debug") => debug = true,
            Some("--check-config") => check = true,
            Some("--config" | "-c") => {
                let value = args
                    .next()
                    .filter(|v| !v.is_empty() && !v.as_bytes().starts_with(b"-"));
                path = value
                    .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?
                    .into();
            }
            _ => {
                if let Some(value) = arg.as_bytes().strip_prefix(b"--config=") {
                    ensure!(!value.is_empty(), "--config requires a path");
                    path = OsStr::from_bytes(value).into();
                } else {
                    bail!("unknown argument: {} (see --help)", arg.to_string_lossy());
                }
            }
        }
    }
    Ok(Command::Run {
        path,
        daemon,
        debug,
        check,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Result<Command> {
        parse(values.iter().map(OsString::from))
    }
    #[test]
    fn defaults_and_aliases() {
        assert_eq!(
            args(&[]).unwrap(),
            Command::Run {
                path: "/etc/ubgp.toml".into(),
                daemon: false,
                debug: false,
                check: false
            }
        );
        for values in [
            &["-c", "custom.toml", "-d"][..],
            &["--daemon", "--config=custom.toml"][..],
        ] {
            assert_eq!(
                args(values).unwrap(),
                Command::Run {
                    path: "custom.toml".into(),
                    daemon: true,
                    debug: false,
                    check: false
                }
            );
        }
        assert!(matches!(
            args(&["--daemon", "--debug"]).unwrap(),
            Command::Run {
                daemon: true,
                debug: true,
                ..
            }
        ));
        assert_eq!(args(&["--help"]).unwrap(), Command::Help);
        assert_eq!(args(&["--version"]).unwrap(), Command::Version);
    }
    #[test]
    fn reject_missing_values_and_unknown_flags() {
        for values in [
            &["--config"][..],
            &["-c", "--daemon"][..],
            &["--config="][..],
            &["--bogus"][..],
        ] {
            assert!(args(values).is_err());
        }
    }
    #[test]
    fn paths_need_not_be_utf8() {
        let path = OsStr::from_bytes(b"config-\xff.toml");
        assert_eq!(
            parse([OsString::from("-c"), path.to_owned()]).unwrap(),
            Command::Run {
                path: path.into(),
                daemon: false,
                debug: false,
                check: false
            }
        );
    }
}
