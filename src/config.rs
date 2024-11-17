use super::peer_blocker::PeerIdRule;

use anyhow::Result;
use serde::Deserialize;

use std::rc::Rc;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_log_config")]
    pub log: LoggerConfig,
    pub aria2_rpc: RpcConfig,
    pub rules: RuleConfig,
    pub ipset: IpsetConfig,
    #[serde(default = "default_option_config")]
    pub option: OptionConfig,
}

#[derive(Debug, Deserialize)]
pub struct LoggerConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub timestamp: bool,
}

#[derive(Debug, Deserialize)]
pub struct RpcConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub secure: bool,
    #[serde(default)]
    pub secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RuleConfig {
    #[serde(default = "default_max_rewind_pieces")]
    pub max_rewind_pieces: u32,
    #[serde(default = "default_max_rewind_percent")]
    pub max_rewind_percent: f64,
    #[serde(default = "default_max_difference")]
    pub max_difference: f64,
    #[serde(deserialize_with = "deserialize_peer_id_rules")]
    pub peer_id_rules: Rc<Vec<PeerIdRule>>,
}

#[derive(Debug, Deserialize)]
pub struct OptionConfig {
    #[serde(default = "default_sampling_count")]
    pub sampling_count: u8,
    #[serde(default = "default_interval")]
    pub interval: u32,
    #[serde(default = "default_exception_interval")]
    pub exception_interval: u32,
    #[serde(default = "default_peer_disconnect_latency")]
    pub peer_disconnect_latency: u32,
    #[serde(default = "default_peer_snapshot_timeout")]
    pub peer_snapshot_timeout: u32,
    #[serde(default = "default_block_duration")]
    pub block_duration: u32,
}

#[derive(Debug, Deserialize)]
pub struct IpsetConfig {
    pub v4: String,
    pub v6: String,
}

impl Config {
    pub fn load_config(filename: &str) -> Result<Config> {
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

fn default_log_config() -> LoggerConfig {
    LoggerConfig {
        level: default_log_level(),
        timestamp: false,
    }
}

fn default_option_config() -> OptionConfig {
    OptionConfig {
        sampling_count: default_sampling_count(),
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
fn default_max_difference() -> f64 {
    0.10
}

#[inline]
fn default_block_duration() -> u32 {
    43200
}

#[inline]
fn default_sampling_count() -> u8 {
    10
}

#[inline]
fn default_interval() -> u32 {
    10
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
