use std::rc::Rc;

use serde::{Deserialize, Deserializer};

/// The method for matching the peer ID
#[derive(Debug, Deserialize)]
pub enum PeerIdRuleMethod {
    #[serde(rename = "STARTS_WITH")]
    StartsWith,
    #[serde(rename = "CONTAINS")]
    Contains,
}

/// Stores the rule for blocking peers based on the peer ID
#[derive(Debug, Deserialize)]
pub struct PeerIdRule {
    pub method: PeerIdRuleMethod,
    #[serde(deserialize_with = "deserialize_peer_id_content_lowercase")]
    pub content: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlockRule {
    /// The maximum allowed number of rewinded pieces
    /// If the peer rewinds more pieces than this value,
    /// and the percentage of rewinded pieces is greater than max_rewind_percent,
    /// the peer will be blocked
    #[serde(default = "BlockRule::default_max_rewind_pieces")]
    pub max_rewind_pieces: u32,
    #[serde(default = "BlockRule::default_max_rewind_percent")]
    pub max_rewind_percent: f64,

    /// The maximum allowed difference between the estimated upload size
    /// and the actual download size reported by the peer
    /// If the difference is greater than this value, the peer will be blocked
    #[serde(default = "BlockRule::default_max_upload_difference")]
    pub max_upload_difference: f64,

    /// The maximum allowed latency from the peer's download completion to the upload speed
    /// reaching zero
    #[serde(default = "BlockRule::default_max_latency_completed_to_zero")]
    pub max_latency_completed_to_zero: u32,

    /// The rules for blocking peers based on the peer ID
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
        // https://docs.pbh-btn.com/docs/module/peer-id/
        let rules = vec![
            ("STARTS_WITH", "-xl"),
            ("STARTS_WITH", "-hp"),
            ("STARTS_WITH", "-xm"),
            ("STARTS_WITH", "-dt"),
            ("STARTS_WITH", "-gt0002"),
            ("STARTS_WITH", "-gt0003"),
            ("STARTS_WITH", "-sd"),
            ("STARTS_WITH", "-xf"),
            ("STARTS_WITH", "-qd"),
            ("STARTS_WITH", "-bn"),
            ("STARTS_WITH", "-dl"),
            ("STARTS_WITH", "-ts"),
            ("STARTS_WITH", "-fg"),
            ("STARTS_WITH", "-tt"),
            ("STARTS_WITH", "-nx"),
            ("CONTAINS", "-rn0.0.0"),
            ("CONTAINS", "cacao"),
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

fn deserialize_peer_id_rules<'de, D>(
    deserializer: D,
) -> std::result::Result<Rc<Vec<PeerIdRule>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let rules = Vec::deserialize(deserializer)?;
    Ok(Rc::new(rules))
}

fn deserialize_peer_id_content_lowercase<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(s.to_lowercase())
}
