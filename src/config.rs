use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
};

/// Upper bound for configurable wall-clock timeouts, excluding the BGP hold timer.
pub(crate) const MAX_TIMEOUT_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default = "port")]
    pub listen_port: u16,
    #[serde(default)]
    pub kernel: Kernel,
    #[serde(default)]
    pub management: Management,
    pub acls: HashMap<String, Acl>,
    pub peers: Vec<Peer>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Management {
    pub enabled: bool,
    pub listen: SocketAddr,
}
impl Default for Management {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1:65090".parse().unwrap(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Kernel {
    pub tables: Vec<u32>,
    pub receive_buffer_bytes: usize,
    pub refresh_interval_ms: u64,
    pub reconcile_interval_secs: u64,
    pub stale_timeout_secs: u64,
    pub dump_timeout_secs: u64,
    pub max_prefixes: usize,
}
impl Default for Kernel {
    fn default() -> Self {
        Self {
            tables: vec![254],
            receive_buffer_bytes: 64 * 1024 * 1024,
            refresh_interval_ms: 250,
            reconcile_interval_secs: 300,
            stale_timeout_secs: 30,
            dump_timeout_secs: 10,
            max_prefixes: 2_000_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub address: IpAddr,
    pub local_address: IpAddr,
    pub interface: String,
    pub remote_asn: u32,
    pub export_acl: String,
    pub md5_password: Option<Md5Key>,
    #[serde(default = "port")]
    pub port: u16,
    #[serde(default = "hold")]
    pub hold_time_secs: u16,
    #[serde(default = "connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "write_timeout")]
    pub write_timeout_secs: u64,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default = "yes")]
    pub ipv4: bool,
    pub next_hop_v4: Option<Ipv4Addr>,
    pub next_hop_v6: Option<Ipv6Addr>,
    pub next_hop_v6_link_local: Option<Ipv6Addr>,
}

/// A shared TCP-MD5 key. Debug output must never expose its contents.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Md5Key(String);
impl std::fmt::Debug for Md5Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}
impl Md5Key {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
fn port() -> u16 {
    179
}
fn hold() -> u16 {
    90
}
fn connect_timeout() -> u64 {
    10
}
fn write_timeout() -> u64 {
    10
}
fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acl {
    pub rules: Vec<Rule>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub action: Action,
    pub prefix: IpNet,
    pub min_length: Option<u8>,
    pub max_length: Option<u8>,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Permit,
    Deny,
}

impl Acl {
    /// Apply the first matching prefix/length rule, denying when no rule matches.
    /// Omitted length bounds require the rule's exact prefix length.
    pub fn permits(&self, prefix: &IpNet) -> bool {
        self.rules
            .iter()
            .find(|r| {
                r.prefix.contains(prefix)
                    && prefix.prefix_len() >= r.min_length.unwrap_or(r.prefix.prefix_len())
                    && prefix.prefix_len() <= r.max_length.unwrap_or(r.prefix.prefix_len())
            })
            .is_some_and(|r| r.action == Action::Permit)
    }
}
/// Reject unspecified, multicast, and limited-broadcast IPv4 addresses.
pub fn valid_v4(a: Ipv4Addr) -> bool {
    !a.is_unspecified() && !a.is_multicast() && a != Ipv4Addr::BROADCAST
}
/// A BGP identifier is a nonzero integer, not necessarily an IPv4 host address.
pub fn valid_router_id(id: Ipv4Addr) -> bool {
    !id.is_unspecified()
}
/// Reject unspecified and multicast IPv6 addresses; link-local addresses are allowed.
pub fn valid_v6(a: Ipv6Addr) -> bool {
    !a.is_unspecified() && !a.is_multicast()
}
impl Peer {
    /// Use the explicit IPv4 next hop, falling back to an IPv4 local transport address.
    pub fn nh4(&self) -> Option<Ipv4Addr> {
        self.next_hop_v4.or(match self.local_address {
            IpAddr::V4(a) => Some(a),
            _ => None,
        })
    }
    /// Use the explicit IPv6 next hop, falling back to an IPv6 local transport address.
    pub fn nh6(&self) -> Option<Ipv6Addr> {
        self.next_hop_v6.or(match self.local_address {
            IpAddr::V6(a) => Some(a),
            _ => None,
        })
    }
}
impl Config {
    /// Read, parse, and validate a TOML configuration without exposing source in errors.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg = Self::parse(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }
    /// Deserialize TOML, replacing parser errors with locations that cannot reveal keys.
    fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|error: toml::de::Error| {
            // TOML's rendered errors include source lines, and even its message
            // may quote values. Preserve location without leaking shared keys.
            let start = error.span().map_or(0, |span| span.start).min(text.len());
            let before = &text.as_bytes()[..start];
            let line = before.iter().filter(|b| **b == b'\n').count() + 1;
            let column = before.iter().rposition(|b| *b == b'\n').map_or(start + 1, |n| start - n);
            anyhow::anyhow!("parsing configuration at line {line}, column {column}: check TOML syntax, field names and types (source omitted to protect secrets)")
        })
    }
    /// Check configuration bounds, ACL references, peer uniqueness, and address families.
    /// Interface existence and local address ownership are checked when connecting.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.management.listen.ip().is_loopback(),
            "management CLI must bind to a loopback address"
        );
        ensure!(
            self.management.listen.port() != 0,
            "management CLI port must be nonzero"
        );
        ensure!(
            self.asn != 0 && self.asn != 23456,
            "local ASN must be nonzero and not AS_TRANS"
        );
        ensure!(valid_router_id(self.router_id), "router_id must be nonzero");
        ensure!(self.listen_port != 0, "listen_port must be nonzero");
        ensure!(!self.peers.is_empty(), "at least one peer is required");
        ensure!(
            !self.kernel.tables.is_empty() && self.kernel.tables.iter().all(|t| *t != 0),
            "select at least one nonzero routing table"
        );
        ensure!(
            (65536..=1024 * 1024 * 1024).contains(&self.kernel.receive_buffer_bytes),
            "receive_buffer_bytes must be 64 KiB..1 GiB"
        );
        ensure!(
            (10..=60000).contains(&self.kernel.refresh_interval_ms),
            "refresh_interval_ms must be 10..60000"
        );
        for (name, seconds) in [
            (
                "reconcile_interval_secs",
                self.kernel.reconcile_interval_secs,
            ),
            ("stale_timeout_secs", self.kernel.stale_timeout_secs),
            ("dump_timeout_secs", self.kernel.dump_timeout_secs),
        ] {
            ensure!(
                (1..=MAX_TIMEOUT_SECS).contains(&seconds),
                "kernel {name} must be 1..={MAX_TIMEOUT_SECS} seconds"
            );
        }
        ensure!(
            self.kernel.dump_timeout_secs < self.kernel.stale_timeout_secs,
            "dump timeout must be shorter than stale timeout"
        );
        ensure!(
            self.kernel.max_prefixes > 0,
            "max_prefixes must be positive"
        );
        for (name, acl) in &self.acls {
            ensure!(!name.is_empty(), "ACL name must not be empty");
            for r in &acl.rules {
                let base = r.prefix.prefix_len();
                let lo = r.min_length.unwrap_or(base);
                let hi = r.max_length.unwrap_or(base);
                let max = if r.prefix.addr().is_ipv4() { 32 } else { 128 };
                ensure!(
                    r.prefix == r.prefix.trunc(),
                    "ACL {name}: prefix must have no host bits"
                );
                ensure!(
                    base <= lo && lo <= hi && hi <= max,
                    "ACL {name}: invalid prefix length range"
                );
            }
        }
        let mut endpoints = HashSet::new();
        for p in &self.peers {
            ensure!(
                p.md5_password.as_ref().is_none_or(
                    |key| (1..=libc::TCP_MD5SIG_MAXKEYLEN).contains(&key.as_bytes().len())
                ),
                "peer {}: md5_password must contain 1..=80 UTF-8 bytes; omit it to disable authentication",
                p.address
            );
            ensure!(
                self.acls.contains_key(&p.export_acl),
                "peer {}: mandatory export ACL {:?} does not exist",
                p.address,
                p.export_acl
            );
            ensure!(
                p.remote_asn != 0 && p.remote_asn != 23456 && p.port != 0,
                "invalid peer ASN or port"
            );
            ensure!(
                p.address != p.local_address && p.address.is_ipv4() == p.local_address.is_ipv4(),
                "peer/local addresses must differ and use the same transport family"
            );
            ensure!(
                match p.address {
                    IpAddr::V4(a) => valid_v4(a),
                    IpAddr::V6(a) => valid_v6(a),
                },
                "invalid peer address"
            );
            ensure!(
                match p.local_address {
                    IpAddr::V4(a) => valid_v4(a),
                    IpAddr::V6(a) => valid_v6(a),
                },
                "invalid local address"
            );
            ensure!(
                !p.interface.is_empty()
                    && p.interface.len() < libc::IFNAMSIZ
                    && !p.interface.contains('\0'),
                "invalid peer interface"
            );
            ensure!(
                endpoints.insert((p.address, p.local_address, p.interface.clone())),
                "duplicate peer endpoint"
            );
            ensure!(
                p.hold_time_secs == 0 || p.hold_time_secs >= 3,
                "hold time must be zero or >= 3 seconds"
            );
            for (name, seconds) in [
                ("connect_timeout_secs", p.connect_timeout_secs),
                ("write_timeout_secs", p.write_timeout_secs),
            ] {
                ensure!(
                    (1..=MAX_TIMEOUT_SECS).contains(&seconds),
                    "peer {}: {name} must be 1..={MAX_TIMEOUT_SECS} seconds",
                    p.address
                );
            }
            ensure!(
                p.ipv4 || p.ipv6,
                "peer must enable at least one address family"
            );
            ensure!(
                self.ipv6
                    || (!p.ipv6
                        && p.address.is_ipv4()
                        && p.next_hop_v6.is_none()
                        && p.next_hop_v6_link_local.is_none()),
                "IPv6 must be enabled globally before using IPv6 settings"
            );
            ensure!(
                !p.ipv4 || p.nh4().is_some_and(valid_v4),
                "IPv4 export requires a valid local next_hop_v4"
            );
            ensure!(
                !p.ipv6
                    || p.nh6()
                        .is_some_and(|a| valid_v6(a) && !a.is_unicast_link_local()),
                "IPv6 export requires a non-link-local next_hop_v6"
            );
            ensure!(
                p.next_hop_v6_link_local
                    .is_none_or(|a| a.is_unicast_link_local()),
                "next_hop_v6_link_local must be link-local"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn md5_keys_are_optional_bounded_by_bytes_and_redacted() {
        let mut c: Config = toml::from_str(include_str!("../examples/ubgp.toml")).unwrap();
        c.validate().unwrap();
        for value in ["x".into(), "x".repeat(80), "é".repeat(40)] {
            c.peers[0].md5_password = Some(Md5Key(value));
            c.validate().unwrap();
        }
        for value in [String::new(), "x".repeat(81), "é".repeat(41)] {
            c.peers[0].md5_password = Some(Md5Key(value));
            assert!(c.validate().is_err());
        }
        c.peers[0].md5_password = Some(Md5Key("test-secret-do-not-print".into()));
        assert!(!format!("{c:?}").contains("test-secret-do-not-print"));
        for text in [
            "md5_password = \"test-secret-do-not-print\" trailing",
            "asn = \"test-secret-do-not-print\"",
        ] {
            let error = Config::parse(text).unwrap_err();
            assert!(!format!("{error:#}").contains("test-secret-do-not-print"));
            assert!(error.to_string().contains("line"));
        }
    }
    #[test]
    fn acl_order_ranges_and_default_deny() {
        let acl: Acl = toml::from_str(
            r#"rules = [
            { action = "deny", prefix = "10.1.0.0/16", min_length = 16, max_length = 32 },
            { action = "permit", prefix = "10.0.0.0/8", min_length = 24, max_length = 28 },
            { action = "permit", prefix = "2001:db8::/32" }
        ]"#,
        )
        .unwrap();
        for p in ["10.2.0.0/24", "10.2.0.0/28", "2001:db8::/32"] {
            assert!(acl.permits(&p.parse().unwrap()), "{p}");
        }
        for p in [
            "10.1.0.0/24",
            "10.2.0.0/29",
            "10.0.0.0/8",
            "0.0.0.0/0",
            "2001:db8::/48",
        ] {
            assert!(!acl.permits(&p.parse().unwrap()), "{p}");
        }
    }
    #[test]
    fn mandatory_acl_and_ipv6_gate() {
        let text = include_str!("../examples/ubgp.toml");
        let mut c: Config = toml::from_str(text).unwrap();
        c.validate().unwrap();
        c.peers[0].export_acl = "missing".into();
        assert!(c.validate().is_err());
        c.peers[0].export_acl = "export".into();
        c.peers[0].ipv6 = true;
        assert!(c.validate().is_err());
        assert!(toml::from_str::<Config>(&text.replace("export_acl = \"export\"", "")).is_err());
    }
    #[test]
    fn router_ids_are_nonzero_integers_without_relaxing_addresses() {
        let mut c: Config = toml::from_str(include_str!("../examples/ubgp.toml")).unwrap();
        for id in ["0.0.0.1", "224.0.0.1", "255.255.255.255"] {
            c.router_id = id.parse().unwrap();
            c.validate().unwrap();
        }
        c.router_id = "0.0.0.0".parse().unwrap();
        assert!(c.validate().is_err());
        assert!(!valid_v4("224.0.0.1".parse().unwrap()));
        assert!(!valid_v4("255.255.255.255".parse().unwrap()));
    }
    #[test]
    fn timeout_bounds_reject_overflowing_toml_and_keep_valid_limits() {
        let text = include_str!("../examples/ubgp.toml");
        let oversized = text.replace(
            "connect_timeout_secs = 10",
            "connect_timeout_secs = 9223372036854775807",
        );
        let invalid = Config::parse(&oversized).unwrap();
        assert!(
            invalid
                .validate()
                .unwrap_err()
                .to_string()
                .contains("connect_timeout_secs")
        );
        let baseline = Config::parse(text).unwrap();
        for value in [0, MAX_TIMEOUT_SECS + 1, i64::MAX as u64, u64::MAX] {
            let mut c = baseline.clone();
            c.peers[0].connect_timeout_secs = value;
            assert!(c.validate().is_err());
            let mut c = baseline.clone();
            c.peers[0].write_timeout_secs = value;
            assert!(c.validate().is_err());
            let mut c = baseline.clone();
            c.kernel.reconcile_interval_secs = value;
            assert!(c.validate().is_err());
            let mut c = baseline.clone();
            c.kernel.stale_timeout_secs = value;
            assert!(c.validate().is_err());
            let mut c = baseline.clone();
            c.kernel.dump_timeout_secs = value;
            assert!(c.validate().is_err());
        }
        for value in [1, MAX_TIMEOUT_SECS] {
            let mut c = baseline.clone();
            c.peers[0].connect_timeout_secs = value;
            c.peers[0].write_timeout_secs = value;
            c.kernel.reconcile_interval_secs = value;
            c.validate().unwrap();
        }
        let mut c = baseline;
        c.kernel.stale_timeout_secs = MAX_TIMEOUT_SECS;
        c.kernel.dump_timeout_secs = MAX_TIMEOUT_SECS - 1;
        c.validate().unwrap();
        c.kernel.dump_timeout_secs = MAX_TIMEOUT_SECS;
        assert!(c.validate().is_err());
    }
}
