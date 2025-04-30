use std::rc::Rc;

use serde::{Deserialize, Deserializer};

/// Method used for peer ID matching
#[derive(Debug, Deserialize)]
pub enum PeerIdRuleMethod {
    /// Checks if peer ID starts with specified string
    #[serde(rename = "STARTS_WITH")]
    StartsWith,
    /// Checks if peer ID contains specified string
    #[serde(rename = "CONTAINS")]
    Contains,
}

/// Rule definition for blocking peers based on their peer ID
#[derive(Debug, Deserialize)]
pub struct PeerIdRule {
    /// Matching method to apply (StartsWith or Contains)
    pub method: PeerIdRuleMethod,
    /// String content to match against peer ID (automatically converted to lowercase)
    #[serde(deserialize_with = "deserialize_peer_id_content_lowercase")]
    pub content: String,
}

/// Configuration of rules used to determine which peers should be blocked
#[derive(Clone, Debug, Deserialize)]
pub struct BlockRule {
    /// Maximum allowed rewind pieces count for a peer
    /// Works in conjunction with max_rewind_percent - peer will be blocked only when
    /// BOTH this value AND max_rewind_percent are exceeded
    #[serde(default = "BlockRule::default_max_rewind_pieces")]
    pub max_rewind_pieces: u32,

    /// Maximum allowed rewind percentage (0.0-1.0) of total length for a peer
    /// Works in conjunction with max_rewind_pieces - peer will be blocked only when
    /// BOTH this value AND max_rewind_pieces are exceeded
    #[serde(default = "BlockRule::default_max_rewind_percent")]
    pub max_rewind_percent: f64,

    /// Maximum allowed ratio difference between estimated upload size and actual download size
    /// reported by peer. If the actual difference ratio exceeds this value, the peer will be
    /// blocked. Value is expressed as a ratio (e.g., 0.20 = 20%)
    #[serde(default = "BlockRule::default_max_upload_difference")]
    pub max_upload_difference: f64,

    /// Maximum allowed seconds between download completion and upload speed
    /// reaching zero. If this time limit is exceeded, the peer will be blocked
    #[serde(default = "BlockRule::default_max_latency_completed_to_zero")]
    pub max_latency_completed_to_zero: u32,

    /// List of rules for blocking peers based on peer ID matching
    #[serde(
        default = "BlockRule::default_peer_id_rules",
        deserialize_with = "deserialize_peer_id_rules"
    )]
    pub peer_id_rules: Rc<Vec<PeerIdRule>>,
}

impl BlockRule {
    #[inline]
    fn default_max_rewind_pieces() -> u32 { 5 }

    #[inline]
    fn default_max_rewind_percent() -> f64 { 0.05 }

    #[inline]
    fn default_max_upload_difference() -> f64 { 0.20 }

    #[inline]
    fn default_max_latency_completed_to_zero() -> u32 { 300 }

    #[inline]
    fn default_peer_id_rules() -> Rc<Vec<PeerIdRule>> {
        // Default rules only contain the most common unwelcome peer IDs:
        // -XL: Xunlei, -SD: Xunlei, -XF: Xfplay, -QD: QQDownload
        let rules = vec![
            ("STARTS_WITH", "-XL"),
            ("STARTS_WITH", "-SD"),
            ("STARTS_WITH", "-XF"),
            ("STARTS_WITH", "-QD"),
        ]
        .into_iter()
        .map(|(method, content)| PeerIdRule {
            method: match method {
                "STARTS_WITH" => PeerIdRuleMethod::StartsWith,
                "CONTAINS" => PeerIdRuleMethod::Contains,
                _ => unreachable!(),
            },
            content: content.to_lowercase(),
        })
        .collect::<Vec<_>>();

        Rc::new(rules)
    }
}

impl Default for BlockRule {
    fn default() -> Self {
        Self {
            max_rewind_pieces: BlockRule::default_max_rewind_pieces(),
            max_rewind_percent: BlockRule::default_max_rewind_percent(),
            max_upload_difference: BlockRule::default_max_upload_difference(),
            max_latency_completed_to_zero: BlockRule::default_max_latency_completed_to_zero(),
            peer_id_rules: BlockRule::default_peer_id_rules(),
        }
    }
}

/// Custom deserializer for peer ID rules that wraps the vector in Rc
fn deserialize_peer_id_rules<'de, D>(
    deserializer: D,
) -> std::result::Result<Rc<Vec<PeerIdRule>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let rules = Vec::deserialize(deserializer)?;
    Ok(Rc::new(rules))
}

/// Custom deserializer that converts peer ID content to lowercase for case-insensitive matching
fn deserialize_peer_id_content_lowercase<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(s.to_lowercase())
}
