use serde::Deserialize;

use super::peer_blocker::{BlockOption, BlockRule, FwOption, Result};

/// Main configuration structure for the Aria2 peer blocker
///
/// This struct contains all configuration parameters necessary to run the application,
/// organized into logical sections. It can be loaded from a TOML configuration file.
/// All sections use their respective default values if not explicitly configured.
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    /// Logger configuration
    #[serde(default)]
    pub log: LoggerConfig,

    /// Aria2 RPC configuration for communicating with the Aria2 daemon
    #[serde(default)]
    pub aria2_rpc: RpcConfig,

    /// Block Rules configuration defining peer behavior that should trigger blocking
    #[serde(default)]
    pub rules: BlockRule,

    /// General options for controlling the peer blocker's behavior
    #[serde(default)]
    pub option: BlockOption,

    /// Options for Linux firewall integration
    #[serde(default)]
    pub firewall: FwOption,
}

/// Logging configuration parameters
///
/// Controls the verbosity and formatting of log output.
#[derive(Debug, Deserialize)]
pub struct LoggerConfig {
    /// Log level, determining which messages are displayed
    ///
    /// Valid values: "off", "error", "warn", "info", "debug", "trace"
    /// Default is "info".
    #[serde(default = "LoggerConfig::default_log_level")]
    pub level: String,

    /// Controls whether to add timestamp to log messages
    ///
    /// When true, each log message will be prefixed with a timestamp.
    /// Default is false.
    #[serde(default)]
    pub timestamp: bool,
}

impl LoggerConfig {
    #[inline]
    fn default_log_level() -> String { "info".to_string() }
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            level: LoggerConfig::default_log_level(),
            timestamp: false,
        }
    }
}

/// Aria2 RPC connection configuration
///
/// Controls how the application connects to and communicates with the Aria2 daemon
/// via its JSON-RPC interface. These settings must match your Aria2 daemon configuration.
#[derive(Debug, Deserialize)]
pub struct RpcConfig {
    /// Aria2 RPC host address
    ///
    /// Hostname or IP address where the Aria2 daemon is running.
    /// Default is "localhost".
    #[serde(default = "RpcConfig::default_host")]
    pub host: String,

    /// Aria2 RPC port number
    ///
    /// Port on which the Aria2 RPC server is listening.
    /// Default is 6800, which is Aria2's default RPC port.
    #[serde(default = "RpcConfig::default_port")]
    pub port: u16,

    /// Whether to use HTTPS for RPC connections
    ///
    /// When true, connections will use HTTPS instead of HTTP.
    /// Default is false.
    #[serde(default)]
    pub secure: bool,

    /// Aria2 RPC secret token for authentication
    ///
    /// Must match the secret token configured in Aria2 (--rpc-secret option).
    /// If None, no authentication will be used.
    #[serde(default)]
    pub secret: Option<String>,

    /// Timeout for RPC requests in seconds
    ///
    /// If an RPC request takes longer than this duration, it will be aborted.
    /// Default is 5 seconds.
    #[serde(default = "RpcConfig::default_timeout")]
    pub timeout: u32,

    /// Maximum number of retry attempts for failed RPC requests
    ///
    /// When an RPC request fails, it will be retried up to this many times.
    /// Default is 3 retries.
    #[serde(default = "RpcConfig::default_max_retries")]
    pub max_retries: u32,
}

impl RpcConfig {
    #[inline]
    fn default_host() -> String { "localhost".to_string() }

    #[inline]
    fn default_port() -> u16 { 6800 }

    #[inline]
    fn default_timeout() -> u32 { 5 }

    #[inline]
    fn default_max_retries() -> u32 { 3 }
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            host: RpcConfig::default_host(),
            port: RpcConfig::default_port(),
            secure: false,
            secret: None,
            timeout: RpcConfig::default_timeout(),
            max_retries: RpcConfig::default_max_retries(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    ///
    /// Will return an error if:
    /// - The file cannot be read
    /// - The file contains invalid TOML
    /// - The TOML cannot be parsed into the Config structure
    pub fn load(filename: &str) -> Result<Config> {
        let config_data = std::fs::read_to_string(filename)?;
        let config: Config = toml::from_str(&config_data)?;
        Ok(config)
    }
}
