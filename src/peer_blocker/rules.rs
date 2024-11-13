use serde::Deserialize;

use std::rc::Rc;

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
    pub content: String,
}

#[derive(Default, Debug, Clone)]
pub struct BlockRule {
    /// The maximum allowed number of rewinded pieces
    /// If the peer rewinds more pieces than this value,
    /// and the percentage of rewinded pieces is greater than max_rewind_percent,
    /// the peer will be blocked
    pub max_rewind_pieces: u32,
    pub max_rewind_percent: f64,

    /// The maximum allowed difference between the estimated upload size
    /// and the actual download size reported by the peer
    /// If the difference is greater than this value, the peer will be blocked
    pub max_difference: f64,

    /// The rules for blocking peers based on the peer ID
    pub peer_id_block_rules: Rc<Vec<PeerIdRule>>,
}

#[derive(Default)]
pub struct BlockRuleBuilder {
    max_rewind_pieces: u32,
    max_rewind_percent: f64,
    max_difference: f64,
    peer_id_block_rules: Rc<Vec<PeerIdRule>>,
}

impl BlockRule {
    pub fn builder() -> BlockRuleBuilder {
        BlockRuleBuilder::default()
    }
}

impl BlockRuleBuilder {
    pub fn max_rewind_pieces(mut self, max_rewind_pieces: u32) -> Self {
        self.max_rewind_pieces = max_rewind_pieces;
        self
    }
    pub fn max_rewind_percent(mut self, max_rewind_percent: f64) -> Self {
        self.max_rewind_percent = max_rewind_percent;
        self
    }
    pub fn max_difference(mut self, max_difference: f64) -> Self {
        self.max_difference = max_difference;
        self
    }
    pub fn peer_id_block_rules(mut self, peer_id_block_rules: Rc<Vec<PeerIdRule>>) -> Self {
        self.peer_id_block_rules = peer_id_block_rules;
        self
    }
    pub fn build(self) -> BlockRule {
        BlockRule {
            max_rewind_pieces: self.max_rewind_pieces,
            max_rewind_percent: self.max_rewind_percent,
            max_difference: self.max_difference,
            peer_id_block_rules: self.peer_id_block_rules,
        }
    }
}
