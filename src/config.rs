use super::peer_blocker::{BlockOption, BlockRule, IPSetOption, Result};

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    /// Logger configuration
    #[serde(default)]
    pub log: LoggerConfig,
    /// Aria2 RPC configuration
    #[serde(default)]
    pub aria2_rpc: RpcConfig,

    /// Block Rules configuration
    #[serde(default)]
    pub rules: BlockRule,

    /// General options
    #[serde(default)]
    pub option: BlockOption,

    /// IPSet configuration
    #[serde(default)]
    pub ipset: IPSetOption,
}

#[derive(Debug, Deserialize)]
pub struct LoggerConfig {
    /// Log level, default to Info
    #[serde(default = "LoggerConfig::default_log_level")]
    pub level: String,
    /// Control whether to add timestamp to log, default to false
    #[serde(default)]
    pub timestamp: bool,
}

#[derive(Debug, Deserialize)]
pub struct RpcConfig {
    /// Aria2 RPC host
    #[serde(default = "RpcConfig::default_host")]
    pub host: String,
    /// Aria2 RPC port
    #[serde(default = "RpcConfig::default_port")]
    pub port: u16,
    /// Aria2 RPC secure flag, default to false
    #[serde(default)]
    pub secure: bool,
    /// Aria2 RPC secret, None if not used
    #[serde(default)]
    pub secret: Option<String>,
}

impl Config {
    pub fn load(filename: &str) -> Result<Config> {
        let config_data = std::fs::read_to_string(filename)?;
        let config: Config = toml::from_str(&config_data)?;
        Ok(config)
    }
}

impl LoggerConfig {
    #[inline]
    fn default_log_level() -> String {
        "info".to_string()
    }
}

impl RpcConfig {
    #[inline]
    fn default_host() -> String {
        "localhost".to_string()
    }
    #[inline]
    fn default_port() -> u16 {
        6800
    }
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            level: LoggerConfig::default_log_level(),
            timestamp: false,
        }
    }
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            host: RpcConfig::default_host(),
            port: RpcConfig::default_port(),
            secure: false,
            secret: None,
        }
    }
}
