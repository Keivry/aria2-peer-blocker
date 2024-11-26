use super::peer_blocker::{PeerIdRule, Result};

use serde::Deserialize;

use std::rc::Rc;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Logger configuration
    #[serde(default = "default_log_config")]
    pub log: LoggerConfig,
    /// Aria2 RPC configuration
    pub aria2_rpc: RpcConfig,
    /// Block Rules configuration
    pub rules: RuleConfig,
    /// IPSet configuration
    pub ipset: IpsetConfig,
    #[serde(default = "default_option_config")]
    /// General options
    pub option: OptionConfig,
}

#[derive(Debug, Deserialize)]
pub struct LoggerConfig {
    /// Log level, default to Info
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Control whether to add timestamp to log, default to false
    #[serde(default)]
    pub timestamp: bool,
}

#[derive(Debug, Deserialize)]
pub struct RpcConfig {
    /// Aria2 RPC host
    pub host: String,
    /// Aria2 RPC port
    pub port: u16,
    /// Aria2 RPC secure flag, default to false
    #[serde(default)]
    pub secure: bool,
    /// Aria2 RPC secret, None if not used
    #[serde(default)]
    pub secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RuleConfig {
    /// Maximum rewind pieces, default to 5
    #[serde(default = "default_max_rewind_pieces")]
    pub max_rewind_pieces: u32,
    /// Maximum rewind percent, default to 5%
    #[serde(default = "default_max_rewind_percent")]
    pub max_rewind_percent: f64,
    /// Maximum allowed difference between upload size between estimated and reported by peer, default to 20%
    #[serde(default = "default_max_upload_difference")]
    pub max_upload_difference: f64,
    /// Maximum allowed latency from peer's download completion to the upload speed reaching zero, default to 30 seconds
    #[serde(default = "default_max_latency_completed_to_zero")]
    pub max_latency_completed_to_zero: u32,
    #[serde(deserialize_with = "deserialize_peer_id_rules")]
    pub peer_id_rules: Rc<Vec<PeerIdRule>>,
}

#[derive(Debug, Deserialize)]
pub struct OptionConfig {
    /// Snapshots count, default to 30
    #[serde(default = "default_snapshots_count")]
    pub snapshots_count: u8,
    /// interval to take snapshot, default to 2 seconds
    #[serde(default = "default_interval")]
    pub interval: u32,
    /// Exception interval, default to 90 seconds
    #[serde(default = "default_exception_interval")]
    pub exception_interval: u32,
    /// Peer disconnect latency, default to 180 seconds
    #[serde(default = "default_peer_disconnect_latency")]
    pub peer_disconnect_latency: u32,
    /// Peer snapshot timeout, default to 300 seconds
    #[serde(default = "default_peer_snapshot_timeout")]
    pub peer_snapshot_timeout: u32,
    /// Block duration, default to 12 hours
    #[serde(default = "default_block_duration")]
    pub block_duration: u32,
}

#[derive(Debug, Deserialize)]
pub struct IpsetConfig {
    /// Control whether to flush ipset on initialization, default to true
    #[serde(default = "default_flush")]
    pub flush: bool,
    /// IPSet name for IPv4
    pub v4: String,
    /// Netmask for IPv4, default to 32
    #[serde(default = "default_netmask_v4")]
    pub netmask_v4: u8,
    /// IPSet name for IPv6
    pub v6: String,
    /// Netmask for IPv6, default to 64
    #[serde(default = "default_netmask_v6")]
    pub netmask_v6: u8,
}

impl Config {
    pub fn load(filename: &str) -> Result<Config> {
        let config_data = std::fs::read_to_string(filename)?;
        let config: Config = toml::from_str(&config_data)?;
        Ok(config)
    }
}

fn deserialize_peer_id_rules<'de, D>(
    deserializer: D,
) -> std::result::Result<Rc<Vec<PeerIdRule>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let rules = Vec::deserialize(deserializer)?;
    Ok(Rc::new(rules))
}

fn default_log_config() -> LoggerConfig {
    LoggerConfig {
        level: default_log_level(),
        timestamp: false,
    }
}

fn default_option_config() -> OptionConfig {
    OptionConfig {
        snapshots_count: default_snapshots_count(),
        interval: default_interval(),
        exception_interval: default_exception_interval(),
        peer_disconnect_latency: default_peer_disconnect_latency(),
        peer_snapshot_timeout: default_peer_snapshot_timeout(),
        block_duration: default_block_duration(),
    }
}

#[inline]
fn default_log_level() -> String {
    "info".to_string()
}

#[inline]
fn default_max_rewind_pieces() -> u32 {
    5
}

#[inline]
fn default_max_rewind_percent() -> f64 {
    0.05
}

#[inline]
fn default_max_upload_difference() -> f64 {
    0.20
}

#[inline]
fn default_max_latency_completed_to_zero() -> u32 {
    30
}

#[inline]
fn default_block_duration() -> u32 {
    43200
}

#[inline]
fn default_snapshots_count() -> u8 {
    30
}

#[inline]
fn default_interval() -> u32 {
    2
}

#[inline]
fn default_exception_interval() -> u32 {
    90
}

#[inline]
fn default_peer_disconnect_latency() -> u32 {
    180
}

#[inline]
fn default_peer_snapshot_timeout() -> u32 {
    300
}

#[inline]
fn default_flush() -> bool {
    true
}

#[inline]
fn default_netmask_v4() -> u8 {
    32
}

#[inline]
fn default_netmask_v6() -> u8 {
    64
}
