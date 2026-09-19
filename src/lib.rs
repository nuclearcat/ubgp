//! Linux announce-only BGP exporter with mandatory outbound prefix ACLs.
//!
//! [`config::Config::load`] parses and validates configuration. [`netlink::run`]
//! publishes complete ACL-filtered kernel snapshots to [`bgp::run`], which owns
//! peer sessions. Received routes are validated and discarded, never installed.
//! The [`wire`] module implements the bounded BGP codec and recovery decisions.
//!
//! ACL rules use first-match semantics with an implicit deny. For example, permit
//! a subnet and its more-specifics while rejecting routes outside it:
//!
//! ```
//! use ubgp::config::{Acl, Action, Rule};
//!
//! let acl = Acl {
//!     rules: vec![Rule {
//!         action: Action::Permit,
//!         prefix: "192.0.2.0/24".parse()?,
//!         min_length: Some(24),
//!         max_length: Some(32),
//!     }],
//! };
//! assert!(acl.permits(&"192.0.2.128/25".parse()?));
//! assert!(!acl.permits(&"198.51.100.0/24".parse()?));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Programmatically constructed configurations must pass [`config::Config::validate`]
//! before starting workers. Linux interface and address ownership checks occur
//! when establishing sessions, after configuration validation.
#![cfg(target_os = "linux")]
pub mod bgp;
pub mod config;
pub mod management;
pub mod netlink;
mod tcp_md5;
mod transport;
pub mod wire;
