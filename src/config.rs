use super::peer_blocker::PeerIdRule;

use anyhow::Result;
use serde::Deserialize;

use std::rc::Rc;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Logger configuration
    #[serde(default)]
    pub log: LoggerConfig,
    /// Aria2 RPC configuration
    pub aria2_rpc: RpcConfig,
    /// Block Rules configuration
    pub rules: RuleConfig,
    /// IPSet configuration
    pub ipset: IpsetConfig,
    /// General options
    #[serde(default)]
    pub option: OptionConfig,
}

#[derive(Debug, Deserialize)]
pub struct LoggerConfig {
    /// Log level, default to Info
    pub level: String,
    /// Control whether to add timestamp to log, default to false
    pub timestamp: bool,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        LoggerConfig {
            level: "info".to_owned(),
            timestamp: false,
        }
    }
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
    /// Maximum difference between pieces, default to 10%
    #[serde(default = "default_max_difference")]
    pub max_difference: f64,
    #[serde(deserialize_with = "deserialize_peer_id_rules")]
    pub peer_id_rules: Rc<Vec<PeerIdRule>>,
}

#[derive(Debug, Deserialize)]
pub struct OptionConfig {
    /// Sampling count, default to 10
    pub sampling_count: u8,
    /// Sampling interval, default to 10
    pub interval: u32,
    /// Exception interval, default to 90
    pub exception_interval: u32,
    /// Peer disconnect latency, default to 180
    pub peer_disconnect_latency: u32,
    /// Peer snapshot timeout, default to 300
    pub peer_snapshot_timeout: u32,
    /// Block duration, default to 12 hours
    pub block_duration: u32,
}

impl Default for OptionConfig {
    fn default() -> Self {
        OptionConfig {
            sampling_count: 10,
            interval: 10,
            exception_interval: 90,
            peer_disconnect_latency: 180,
            peer_snapshot_timeout: 300,
            block_duration: 43200,
        }
    }
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

fn deserialize_peer_id_rules<'de, D>(deserializer: D) -> Result<Rc<Vec<PeerIdRule>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let rules = Vec::deserialize(deserializer)?;
    Ok(Rc::new(rules))
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
fn default_max_difference() -> f64 {
    0.10
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
