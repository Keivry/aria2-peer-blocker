use std::time::Duration;

use serde::Deserialize;

/// Configuration options for the peer blocking subsystem
///
/// This struct defines the parameters that control the monitoring frequency,
/// timing thresholds, and block duration for problematic peers.
#[derive(Clone, Debug, Deserialize)]
pub struct BlockOption {
    /// Maximum number of peer info snapshots to keep in memory for each peer
    /// Higher values provide more accurate detection but use more memory
    #[serde(default = "BlockOption::default_snapshots_count")]
    pub snapshots_count: u8,

    /// Time interval (in seconds) between each peer snapshot collection
    /// Controls how frequently peer behavior is sampled
    #[serde(default = "BlockOption::default_interval")]
    pub interval: Duration,

    /// Special interval (in seconds) delay applied when exception accurred
    /// while querying peers information from aria2
    #[serde(default = "BlockOption::default_exception_interval")]
    pub exception_interval: Duration,

    /// Time period (in seconds) to retain peer snapshots in memory
    /// This should be set to a value greater than snapshots_count * interval
    /// Snapshots older than this value will be purged
    #[serde(default = "BlockOption::default_peer_snapshot_timeout")]
    pub peer_snapshot_timeout: u32,

    /// Estimated time (in seconds) for aria2 to disconnect a peer after it has been blocked,
    /// Used for avoid duplicate blocking of the same peer, peer blocked multiple times in this
    /// time will be ignored
    #[serde(default = "BlockOption::default_peer_disconnect_latency")]
    pub peer_disconnect_latency: u32,

    /// Duration (in seconds) that a peer remains blocked
    /// Once this period expires, the peer will be removed from the block list
    #[serde(default = "BlockOption::default_block_duration")]
    pub block_duration: Duration,
}

impl BlockOption {
    #[inline]
    fn default_snapshots_count() -> u8 { 60 }

    #[inline]
    fn default_interval() -> Duration { Duration::from_secs(1) }

    #[inline]
    fn default_exception_interval() -> Duration { Duration::from_secs(90) }

    #[inline]
    fn default_peer_snapshot_timeout() -> u32 { 1800 }

    #[inline]
    fn default_peer_disconnect_latency() -> u32 { 300 }

    #[inline]
    fn default_block_duration() -> Duration { Duration::from_secs(43200) }
}

impl Default for BlockOption {
    fn default() -> Self {
        Self {
            snapshots_count: BlockOption::default_snapshots_count(),
            interval: BlockOption::default_interval(),
            exception_interval: BlockOption::default_exception_interval(),
            peer_snapshot_timeout: BlockOption::default_peer_snapshot_timeout(),
            peer_disconnect_latency: BlockOption::default_peer_disconnect_latency(),
            block_duration: BlockOption::default_block_duration(),
        }
    }
}
