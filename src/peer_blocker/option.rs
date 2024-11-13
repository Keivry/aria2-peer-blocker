#[derive(Default, Debug, Clone)]
pub struct BlockOption {
    /// The number of snapshots to keep for each peer
    pub sampling_count: u8,
    /// The interval between each snapshot, in seconds
    pub sampling_interval: u32,
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
    sampling_count: u8,
    sampling_interval: u32,
    peer_snapshot_timeout: u32,
    peer_disconnect_latency: u32,
}

impl BlockOptionBuilder {
    pub fn sampling_count(mut self, sampling_count: u8) -> Self {
        self.sampling_count = sampling_count;
        self
    }

    pub fn sampling_interval(mut self, sampling_interval: u32) -> Self {
        self.sampling_interval = sampling_interval;
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
            sampling_count: self.sampling_count,
            sampling_interval: self.sampling_interval,
            peer_snapshot_timeout: self.peer_snapshot_timeout,
            peer_disconnect_latency: self.peer_disconnect_latency,
        }
    }
}
