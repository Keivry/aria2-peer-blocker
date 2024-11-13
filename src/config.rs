use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub enum RuleMethod {
    #[serde(rename = "STARTS_WITH")]
    StartsWith,
    #[serde(rename = "CONTAINS")]
    Contains,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub method: RuleMethod,
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub rpc_host: String,
    pub rpc_port: u16,

    pub rpc_secure: bool,

    #[serde(default)]
    pub rpc_secret: Option<String>,

    pub block_peer_id_rules: Vec<Rule>,

    #[serde(default = "default_peer_history_count")]
    pub peer_history_count: u8,

    #[serde(default = "default_interval")]
    pub interval: u32,
    #[serde(default = "default_exception_interval")]
    pub exception_interval: u32,

    pub xt_recent_table: String,
    pub xt_recent_table_v6: String,
}

#[inline]
fn default_interval() -> u32 {
    5
}

#[inline]
fn default_exception_interval() -> u32 {
    60
}

#[inline]
fn default_peer_history_count() -> u8 {
    3
}
