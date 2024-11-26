#[derive(Default, Debug, Clone)]
pub struct BlockOption {
    /// The number of snapshots to keep for each peer
    pub snapshots_count: u8,
    /// The interval between each snapshot, in seconds
    pub interval: u32,
    /// Seconds to keep the peer snapshots
    pub peer_snapshot_timeout: u32,
    /// Seconds to aria2 disconnect the peer after blocking
    pub peer_disconnect_latency: u32,
}

impl BlockOption {
    pub fn builder() -> BlockOptionBuilder {
        BlockOptionBuilder::default()
    }
}

#[derive(Default)]
pub struct BlockOptionBuilder {
    snapshots_count: u8,
    interval: u32,
    peer_snapshot_timeout: u32,
    peer_disconnect_latency: u32,
}

impl BlockOptionBuilder {
    pub fn snapshots_count(mut self, snapshots_count: u8) -> Self {
        self.snapshots_count = snapshots_count;
        self
    }

    pub fn interval(mut self, interval: u32) -> Self {
        self.interval = interval;
        self
    }

    pub fn peer_snapshot_timeout(mut self, peer_snapshot_timeout: u32) -> Self {
        self.peer_snapshot_timeout = peer_snapshot_timeout;
        self
    }

    pub fn peer_disconnect_latency(mut self, peer_disconnect_latency: u32) -> Self {
        self.peer_disconnect_latency = peer_disconnect_latency;
        self
    }

    pub fn build(self) -> BlockOption {
        BlockOption {
            snapshots_count: self.snapshots_count,
            interval: self.interval,
            peer_snapshot_timeout: self.peer_snapshot_timeout,
            peer_disconnect_latency: self.peer_disconnect_latency,
        }
    }
}
