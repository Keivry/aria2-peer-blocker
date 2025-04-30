use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

use aria2_ws::{
    Client,
    response::{Peer, Status as TaskStatus},
};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use percent_encoding::percent_decode;
use tokio::{
    sync::RwLock,
    time::{interval, sleep, timeout},
};

use super::{
    super::{
        Result,
        ipset::IPSetOption,
        option::BlockOption,
        rules::{BlockRule, PeerIdRule, PeerIdRuleMethod},
        utils::timestamp,
    },
    builder::BlockerBuilder,
    executor::Executor,
};

pub struct Blocker {
    /// The aria2 server URL
    pub(super) url: String,
    /// The secret token for the aria
    pub(super) secret: Option<String>,

    /// Rpc timeout in seconds
    pub(super) timeout: Duration,

    /// Rpc request max retries
    pub(super) max_retries: u32,

    /// The websocket rpc client for interacting with the aria2 server
    pub(super) client: Arc<RwLock<Option<Client>>>,

    /// The rules for blocking peers
    pub(super) rule: BlockRule,

    /// The options for blocking peers
    pub(super) option: BlockOption,

    /// The options for ipset
    pub(super) ipset: IPSetOption,

    /// The cache for storing the blocklist and peer snapshots
    pub(super) cache: Arc<RwLock<Cache>>,
}

/// The status of a peer being blocked
#[derive(Debug, Clone, PartialEq)]
enum BlockStatus {
    Unblocked,                    // Not blocked
    EmptyPeerId,                  // Empty peer ID
    IllegalBitfield,              // Empty bitfield
    BlockByPeerId(String),        // Blocked by peer ID with peer id prefix
    BlockByRewind(u32, f64),      // Blocked by rewinding pieces count and percentage
    BlockByUploadDifference(f64), // Blocked by upload progress difference
    BlockByCompletedLatency(u32), // Blocked by download completion to zero latency
    AlreadyBlocked(String),       // Already blocked
}

/// Snapshots of a peer's download progress
#[derive(Debug, Clone)]
struct PeerSnapshot {
    upload_speed: u64, // The client's upload speed to the peer
    percentage: f64,   // The peer's download progress percentage
    bitfield: String,  // The peer's bitfield
}

pub(super) struct Cache {
    /// The blocklist stores the blocked IP, block status and the timestamp when they were blocked
    /// Used for checking if the peer is already blocked before aria2 disconnects it
    /// The IP addresses will be removed from the blocklist after the peer_disconnect_latency
    /// duration
    blocklist: DashMap<IpAddr, (BlockStatus, u64)>,

    /// The peer_snapshots stores the snapshots of the peer's download progress,
    /// and the timestamp when the last snapshot was taken
    /// Used for checking if the peer is rewinding or uploading too much data
    /// The snapshots will be removed after the peer_snapshot_timeout duration
    peer_snapshots: DashMap<IpAddr, (VecDeque<PeerSnapshot>, u64)>,
}

impl Blocker {
    pub fn builder() -> BlockerBuilder { BlockerBuilder::new() }

    pub async fn start(&mut self) {
        // Initialize Blocker
        while let Err(e) = self.initialize().await {
            error!("Initialization error: {:?}", e);
            sleep(self.option.exception_interval).await;
        }

        // Initialize Executor
        let mut executor_v4 = Executor::new(
            &self.ipset.v4,
            self.ipset.netmask_v4,
            self.option.block_duration.as_secs() as u32,
            self.ipset.flush,
        );
        let mut executor_v6 = Executor::new(
            &self.ipset.v6,
            self.ipset.netmask_v6,
            self.option.block_duration.as_secs() as u32,
            self.ipset.flush,
        );

        // Get blocked peers and write to ipset
        loop {
            match self.retry(|| self.get_blocked_peers()).await {
                Ok((ipv4, ipv6)) => {
                    debug!("BLOCKED IPV4 PEERS: {:?}", ipv4);
                    debug!("BLOCKED IPV6 PEERS: {:?}", ipv6);

                    // Update ipset
                    executor_v4
                        .update(&ipv4)
                        .unwrap_or_else(|_| error!("Error updating IPSet [{}]!", self.ipset.v4));
                    executor_v6
                        .update(&ipv6)
                        .unwrap_or_else(|_| error!("Error updating IPSet [{}]!", self.ipset.v6));

                    sleep(self.option.interval).await;
                }
                Err(e) => {
                    warn!("Error getting blocked peers: {:?}", e);
                    sleep(self.option.exception_interval).await;
                }
            }
        }
    }

    /// Initialize the Blocker and start the cache cleaning task
    async fn initialize(&mut self) -> Result<()> {
        self.ensure_connected().await;

        let cache = self.cache.clone();
        let disconnect_latency = self.option.peer_disconnect_latency;
        let snapshot_timeout = self.option.peer_snapshot_timeout;

        // Spawn a task to clean the cache periodically
        let mut interval = interval(self.option.interval);
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                cache
                    .write()
                    .await
                    .clean(disconnect_latency, snapshot_timeout);
            }
        });
        Ok(())
    }

    /// Ensure the client is connected to the Aria2 RPC server
    async fn ensure_connected(&self) {
        if !self.is_connected().await {
            self.reconnect().await;
        }
    }

    /// Check if the client is connected to the Aria2 RPC server
    async fn is_connected(&self) -> bool {
        if let Some(client) = self.client.read().await.as_ref() {
            if let Ok(Ok(_)) = timeout(self.timeout, client.get_version()).await {
                return true;
            }
        }
        false
    }

    /// Reconnect to the Aria2 RPC server
    async fn reconnect(&self) {
        loop {
            match timeout(
                self.timeout,
                Client::connect(&self.url, self.secret.as_deref()),
            )
            .await
            {
                Ok(Ok(client)) => {
                    self.client.write().await.replace(client);
                    if self.is_connected().await {
                        info!("Connected to Aria2 RPC [{}]", self.url);
                        break;
                    } else {
                        error!(
                            "Connected to Aria2 RPC [{}], but checking failed.",
                            self.url
                        );
                    }
                }
                Ok(Err(e)) => {
                    error!("Error connecting to Aria2 RPC: {:?}", e);
                }
                Err(e) => {
                    error!("Timeout connecting to Aria2 RPC: {:?}", e);
                }
            }
            sleep(self.option.exception_interval).await;
        }
    }

    /// Retry the action with a timeout and a maximum number of retries
    async fn retry<F, T, V>(&self, action: F) -> Result<V>
    where
        F: Fn() -> T,
        T: Future<Output = Result<V>>,
    {
        let mut retries = 0;
        while retries < self.max_retries {
            match timeout(self.timeout, action()).await {
                Ok(result) => return result,
                Err(_) => warn!("Timeout occurred during action, retrying..."),
            }
            sleep(self.option.exception_interval).await;
            // ensure connection is established before retry
            self.ensure_connected().await;

            retries += 1;
        }
        Err("Max retries exceeded during action".into())
    }

    /// Get the set of blocked peers for all active BitTorrent tasks,
    /// separated by IPv4 and IPv6
    async fn get_blocked_peers(&self) -> Result<(HashSet<IpAddr>, HashSet<IpAddr>)> {
        let tasks = self.get_active_bittorrent_tasks().await?;
        let mut ipv4 = HashSet::new();
        let mut ipv6 = HashSet::new();
        for task in tasks {
            self.process_task(&task, &mut ipv4, &mut ipv6).await?;
        }
        Ok((ipv4, ipv6))
    }

    /// Process a single BitTorrent task and update the sets of blocked peers
    async fn process_task(
        &self,
        task: &TaskStatus,
        ipv4: &mut HashSet<IpAddr>,
        ipv6: &mut HashSet<IpAddr>,
    ) -> Result<()> {
        for peer in self
            .client
            .read()
            .await
            .as_ref()
            .unwrap()
            .get_peers(&task.gid)
            .await?
        {
            self.process_peer(peer, task, ipv4, ipv6).await?;
        }
        Ok(())
    }

    /// Process a single peer and update the sets of blocked peers
    async fn process_peer(
        &self,
        peer: Peer,
        task: &TaskStatus,
        ipv4: &mut HashSet<IpAddr>,
        ipv6: &mut HashSet<IpAddr>,
    ) -> Result<()> {
        let ip = peer.ip.parse().unwrap();
        let peer_id = percent_decode(peer.peer_id.as_bytes())
            .decode_utf8_lossy()
            .to_lowercase();
        let peer_snapshot = PeerSnapshot {
            upload_speed: peer.upload_speed,
            percentage: percentage(&peer.bitfield, task.num_pieces),
            bitfield: peer.bitfield,
        };
        let timestamp = timestamp();

        let block_status = self
            .determine_block_status(ip, &peer_id, &peer_snapshot, task)
            .await;

        match block_status {
            BlockStatus::AlreadyBlocked(_) => (),
            BlockStatus::Unblocked => self.take_snapshot(ip, &peer_snapshot, timestamp).await,
            _ => {
                match ip {
                    IpAddr::V4(_) => ipv4.insert(ip),
                    IpAddr::V6(_) => ipv6.insert(ip),
                };
                self.register_block(ip, &block_status).await;
            }
        }
        Ok(())
    }

    /// Determine the block status of a peer based on various criteria
    async fn determine_block_status(
        &self,
        ip: IpAddr,
        peer_id: &str,
        peer_snapshot: &PeerSnapshot,
        task: &TaskStatus,
    ) -> BlockStatus {
        if let BlockStatus::AlreadyBlocked(s) = self.match_already_blocked(ip).await {
            // log AlreadyBlocked in debug level
            debug!("BLOCK [{}] FOR [ALREADY BLOCKED: <{}>]", padding(ip), s);
            BlockStatus::AlreadyBlocked(s)
        } else if self.match_empty_peer_id(peer_id) == BlockStatus::EmptyPeerId {
            info!("BLOCK [{}] FOR [EMPTY PEER ID]", padding(ip));
            BlockStatus::EmptyPeerId
        } else if let BlockStatus::BlockByPeerId(peer_id_prefix) = self.match_peer_id_block(peer_id)
        {
            info!("BLOCK [{}] FOR [PEER ID: {}]", padding(ip), peer_id_prefix);
            BlockStatus::BlockByPeerId(peer_id_prefix)
        } else if self.match_illegal_bitfield(peer_snapshot) == BlockStatus::IllegalBitfield {
            info!("BLOCK [{}] FOR [EMPTY BITFIELD]", padding(ip));
            BlockStatus::IllegalBitfield
        } else if let BlockStatus::BlockByRewind(pieces, percent) =
            self.match_rewind_block(ip, peer_snapshot).await
        {
            info!(
                "BLOCK [{}] FOR [REWIND PIECES: {}] [REWIND PERCENTAGE: {:.2}%]",
                padding(ip),
                pieces,
                percent * 100.0
            );
            BlockStatus::BlockByRewind(pieces, percent)
        } else if let BlockStatus::BlockByCompletedLatency(latency) =
            self.match_completed_latency(ip, peer_snapshot).await
        {
            info!(
                "BLOCK [{}] FOR [COMPLETED LATENCY: {}]",
                padding(ip),
                latency
            );
            BlockStatus::BlockByCompletedLatency(latency)
        } else if let BlockStatus::BlockByUploadDifference(percent) =
            self.match_upload_data_block(ip, peer_snapshot, task).await
        {
            info!(
                "BLOCK [{}] FOR [UPLOAD DIFFERENCE: {:.2}%]",
                padding(ip),
                percent * 100.0
            );
            BlockStatus::BlockByUploadDifference(percent)
        } else {
            BlockStatus::Unblocked
        }
    }

    /// Get the list of active BitTorrent tasks
    async fn get_active_bittorrent_tasks(&self) -> Result<Vec<TaskStatus>> {
        Ok(self
            .client
            .read()
            .await
            .as_ref()
            .unwrap()
            .tell_active()
            .await?
            .iter()
            .filter(|task| task.seeder.is_some()) // 'seeder' is only in BitTorrent task
            .cloned()
            .collect())
    }

    /// Check if the peer is already blocked
    async fn match_already_blocked(&self, ip: IpAddr) -> BlockStatus {
        if let Some(entry) = self.cache.read().await.blocklist.get(&ip) {
            let (status, t) = entry.value();
            if timestamp() - *t < self.option.peer_disconnect_latency as u64 {
                let s = match status {
                    BlockStatus::EmptyPeerId => "EmptyPeerId",
                    BlockStatus::IllegalBitfield => "EmptyBitfield",
                    BlockStatus::BlockByPeerId(_) => "BlockByPeerId",
                    BlockStatus::BlockByRewind(..) => "BlockByRewind",
                    BlockStatus::BlockByUploadDifference(_) => "BlockByUploadDifference",
                    BlockStatus::BlockByCompletedLatency(_) => "BlockByCompletedLatency",
                    _ => "",
                };
                return BlockStatus::AlreadyBlocked(s.to_owned());
            }
        }
        BlockStatus::Unblocked
    }

    /// Check if the peer should be blocked based on the peer ID
    fn match_peer_id_block(&self, peer_id: &str) -> BlockStatus {
        match match_rule(peer_id, &self.rule.peer_id_rules) {
            true => BlockStatus::BlockByPeerId(peer_id.get(..8).unwrap_or("TOOSHORT").to_string()),
            false => BlockStatus::Unblocked,
        }
    }

    fn match_empty_peer_id(&self, peer_id: &str) -> BlockStatus {
        // Mark peer_id full of '\0' as empty
        match peer_id.is_empty() || peer_id == "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" {
            true => BlockStatus::EmptyPeerId,
            false => BlockStatus::Unblocked,
        }
    }

    fn match_illegal_bitfield(&self, peer: &PeerSnapshot) -> BlockStatus {
        // Mark empty bitfield or percentage greater than 1.0 as illegal
        match peer.bitfield.is_empty() || peer.percentage > 1.0 {
            true => BlockStatus::IllegalBitfield,
            false => BlockStatus::Unblocked,
        }
    }

    /// Check if the peer should be blocked based on the rewinded pieces and rewinded percent
    async fn match_rewind_block(&self, ip: IpAddr, peer: &PeerSnapshot) -> BlockStatus {
        debug!(
            "PEER DETAIL: [{}], BITFIELD: [{:.20}], PERCENTAGE: [{:.2}%]",
            ip,
            peer.bitfield,
            peer.percentage * 100.0
        );
        if let Some(entry) = self.cache.read().await.peer_snapshots.get(&ip) {
            let (snapshots, _) = entry.value();
            if let Some(last) = snapshots.back() {
                // Check if the peer is rewinding
                let rewind_pieces = rewind_pieces(&last.bitfield, &peer.bitfield);
                debug!(
                    "PEER DETAIL: [{}], LAST BITFIELD: [{:.20}], REWIND PIECES: [{}]",
                    ip, last.bitfield, rewind_pieces
                );
                if rewind_pieces > self.rule.max_rewind_pieces {
                    debug!(
                        "PEER DETAIL: [{}], LAST PERCENTAGE: [{:.2}%]",
                        ip,
                        last.percentage * 100.0
                    );
                    if last.percentage > peer.percentage {
                        let rewind_percent = last.percentage - peer.percentage;
                        debug!(
                            "PEER DETAIL: [{}], REWIND PERCENTAGE: [{:.2}%]",
                            ip,
                            rewind_percent * 100.0
                        );
                        if rewind_percent > self.rule.max_rewind_percent {
                            return BlockStatus::BlockByRewind(rewind_pieces, rewind_percent);
                        }
                    }
                }
            }
        }
        BlockStatus::Unblocked
    }

    /// Check if the peer should be blocked based on the download completion to zero upload speed
    /// latency
    async fn match_completed_latency(&self, ip: IpAddr, peer: &PeerSnapshot) -> BlockStatus {
        if let Some(entry) = self.cache.read().await.peer_snapshots.get(&ip) {
            let (snapshots, _) = entry.value();
            if peer.percentage == 1.0 && !snapshots.is_empty() {
                let latency = match peer.upload_speed {
                    0 => snapshots
                        .iter()
                        .position(|s| s.upload_speed == 0)
                        .unwrap_or(snapshots.len()),
                    _ => snapshots.len() + 1,
                } as u32
                    * self.option.interval.as_secs() as u32;

                debug!("PEER DETAIL: [{}], COMPLETED LATENCY: [{}]", ip, latency);
                if latency > self.rule.max_latency_completed_to_zero {
                    return BlockStatus::BlockByCompletedLatency(latency);
                }
            }
        }
        BlockStatus::Unblocked
    }

    /// Check if the peer should be blocked based on the estimated upload size
    async fn match_upload_data_block(
        &self,
        ip: IpAddr,
        peer: &PeerSnapshot,
        task: &TaskStatus,
    ) -> BlockStatus {
        if let Some(entry) = self.cache.read().await.peer_snapshots.get(&ip) {
            let (snapshots, _) = entry.value();
            if snapshots.len() == self.option.snapshots_count as usize {
                let estimated_upload: u64 =
                    snapshots.iter().map(|peer| peer.upload_speed).sum::<u64>()
                        * self.option.interval.as_secs();
                debug!(
                    "PEER DETAIL: [{}], ESTIMATED UPLOAD: [{}]",
                    ip, estimated_upload
                );
                if estimated_upload == 0 {
                    return BlockStatus::Unblocked;
                }

                let peer_download =
                        // Calculate the number of pieces downloaded by the peer
                        rewind_pieces(&peer.bitfield, &snapshots.front().unwrap().bitfield) as u64
                            * task.piece_length;
                debug!("PEER DETAIL: [{}], PEER DOWNLOAD: [{}]", ip, peer_download);
                if estimated_upload <= peer_download {
                    return BlockStatus::Unblocked;
                }

                let diff = (estimated_upload - peer_download) as f64 / estimated_upload as f64;
                debug!("PEER DETAIL: [{}], DIFFERENCE: [{}]", ip, diff);

                if diff > self.rule.max_upload_difference {
                    return BlockStatus::BlockByUploadDifference(diff);
                }
            }
        }
        BlockStatus::Unblocked
    }

    /// Register the IP address to the blocklist
    async fn register_block(&self, ip: IpAddr, status: &BlockStatus) {
        self.cache
            .write()
            .await
            .blocklist
            .insert(ip, (status.clone(), timestamp()));
    }

    /// Store the snapshot of the peer's download progress
    async fn take_snapshot(&self, ip: IpAddr, peer: &PeerSnapshot, timestamp: u64) {
        self.cache
            .write()
            .await
            .peer_snapshots
            .entry(ip)
            .and_modify(|(snapshots, t)| {
                // Remove the oldest snapshot if the snapshots count exceeds the limit
                if snapshots.len() == self.option.snapshots_count as usize {
                    snapshots.pop_front();
                }

                snapshots.push_back(peer.clone());

                // Update the timestamp of the last snapshot
                *t = timestamp;
            })
            .or_insert_with(|| (VecDeque::from([peer.clone()]), timestamp));
    }
}

impl Cache {
    pub(super) fn empty() -> Self {
        Cache {
            blocklist: DashMap::new(),
            peer_snapshots: DashMap::new(),
        }
    }

    /// Removing the expired blocklist and peer snapshots
    pub(super) fn clean(&mut self, disconnect_latency: u32, snapshot_timeout: u32) {
        let now = timestamp();
        let disconnect_timeout = disconnect_latency as u64;
        let snapshot_timeout = snapshot_timeout as u64;

        self.blocklist
            .retain(|_, (_, t)| now - *t < disconnect_timeout);
        self.peer_snapshots
            .retain(|_, (_, t)| now - *t < snapshot_timeout);

        debug!(
            "Cache stats - Blocklist: {}, Snapshots: {}",
            self.blocklist.len(),
            self.peer_snapshots.len()
        );
    }
}

/// Check if the peer ID matches any of the rules
fn match_rule(peer_id: &str, rules: &[PeerIdRule]) -> bool {
    rules.iter().any(|rule| match rule.method {
        PeerIdRuleMethod::StartsWith => peer_id.starts_with(&rule.content),
        PeerIdRuleMethod::Contains => peer_id.contains(&rule.content),
    })
}

/// Calculate the number of rewinded pieces
fn rewind_pieces(base: &str, bitfield: &str) -> u32 {
    let last_bits = match hex::decode(base) {
        Ok(bits) => bits,
        Err(_) => return 0,
    };
    let current_bits = match hex::decode(bitfield) {
        Ok(bits) => bits,
        Err(_) => return 0,
    };

    last_bits
        .iter()
        .zip(current_bits.iter())
        .map(|(last_byte, current_byte)| (last_byte ^ (last_byte & current_byte)).count_ones())
        .sum()
}

/// Calculate the percentage of pieces downloaded by the peer
fn percentage(bitfield: &str, pieces_count: u64) -> f64 {
    let bitfield_bytes = match hex::decode(bitfield) {
        Ok(bits) => bits,
        Err(_) => return 0.0,
    };

    let total_bits = pieces_count as f64;
    let set_bits = bitfield_bytes
        .iter()
        .map(|byte| byte.count_ones() as u64)
        .sum::<u64>() as f64;
    set_bits / total_bits
}

/// Padding the IP address for better display
fn padding(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => format!("{:^width$}", ip, width = 15),
        IpAddr::V6(ip) => format!("{:^width$}", ip, width = 39),
    }
}
