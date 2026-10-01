/// This release, from Cargo.toml (Semantic Versioning; see CHANGELOG.md).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod account;
pub mod alert;
pub mod catalog;
pub mod control;
pub mod custom;
pub mod dns;
pub mod domain;
pub mod exit_watch;
pub mod logging;
pub mod mail;
pub mod notify;
pub mod platform;
pub mod policy;
pub mod probe;
pub mod proton;
pub mod reconcile;
pub mod redact;
pub mod sessions;
pub mod state;
pub mod tailscale;
pub mod usage;
pub mod wireguard;
