use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct BlockOption {
    /// The number of snapshots to keep for each peer
    #[serde(default = "BlockOption::default_snapshots_count")]
    pub snapshots_count: u8,

    /// The interval between each snapshot, in seconds
    #[serde(default = "BlockOption::default_interval")]
    pub interval: u32,

    /// The interval delay when the peer is in exception state
    #[serde(default = "BlockOption::default_exception_interval")]
    pub exception_interval: u32,

    /// Seconds to keep the peer snapshots
    #[serde(default = "BlockOption::default_peer_snapshot_timeout")]
    pub peer_snapshot_timeout: u32,

    /// Seconds to aria2 disconnect the peer after blocking
    #[serde(default = "BlockOption::default_peer_disconnect_latency")]
    pub peer_disconnect_latency: u32,

    /// Seconds to block the peer
    #[serde(default = "BlockOption::default_block_duration")]
    pub block_duration: u32,
}

impl BlockOption {
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
    fn default_peer_snapshot_timeout() -> u32 {
        300
    }

    #[inline]
    fn default_peer_disconnect_latency() -> u32 {
        300
    }

    #[inline]
    fn default_block_duration() -> u32 {
        43200
    }
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
