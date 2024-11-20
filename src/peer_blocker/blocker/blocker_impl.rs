use super::{
    super::{
        rules::{PeerIdRule, PeerIdRuleMethod},
        utils::timestamp,
        Result,
    },
    builder::PeerBlockerBuilder,
    {BlockStatus, Blocker, PeerSnapshot},
};

use aria2_ws::response::Status as TaskStatus;
use log::{debug, info};
use percent_encoding::percent_decode;

use std::{collections::VecDeque, net::IpAddr};

impl Blocker {
    pub fn builder() -> PeerBlockerBuilder {
        PeerBlockerBuilder::default()
    }

    /// Get the list of blocked peers for all active BitTorrent tasks
    pub async fn get_blocked_peers(&self) -> Result<Vec<IpAddr>> {
        let tasks = self.get_active_bittorrent_tasks().await?;
        let mut peers = Vec::new();
        for task in tasks {
            self.client
                .get_peers(&task.gid)
                .await?
                .into_iter()
                .for_each(|peer| {
                    let ip = peer.ip.parse().unwrap();
                    let peer_id = percent_decode(peer.peer_id.as_bytes())
                        .decode_utf8_lossy()
                        .to_lowercase();
                    let peer_snapshot = PeerSnapshot {
                        upload_speed: peer.upload_speed,
                        percentage: percentage(&peer.bitfield, task.num_pieces),
                        bitfield: peer.bitfield,
                    };

                    let block_status =
                        if let BlockStatus::AlreadyBlocked(s) = self.match_already_blocked(ip) {
                            debug!("BLOCK: [{}] [ALREADY BLOCKED: <{}>]", ip, s);
                            BlockStatus::AlreadyBlocked(s)
                        } else if self.match_empty_peer_id(&peer_id) == BlockStatus::EmptyPeerId {
                            info!("BLOCK: [{}] [EMPTY PEER ID]", ip);
                            BlockStatus::EmptyPeerId
                        } else if let BlockStatus::BlockByPeerId(peer_id_prefix) =
                            self.match_peer_id_block(&peer_id)
                        {
                            info!("BLOCK: [{}] [PEER ID: {}]", ip, peer_id_prefix);
                            BlockStatus::BlockByPeerId(peer_id_prefix)
                        } else if self.match_illegal_bitfield(&peer_snapshot)
                            == BlockStatus::IllegalBitfield
                        {
                            info!("BLOCK: [{}] [EMPTY BITFIELD]", ip);
                            BlockStatus::IllegalBitfield
                        } else if let BlockStatus::BlockByRewind(pieces, percent) =
                            self.match_rewind_block(ip, &peer_snapshot)
                        {
                            info!(
                                "BLOCK: [{}] [REWIND PIECES: {}] [REWIND PERCENTAGE: {:.2}%]",
                                ip,
                                pieces,
                                percent * 100.0
                            );
                            BlockStatus::BlockByRewind(pieces, percent)
                        } else if let BlockStatus::BlockByCompletedLatency(latency) =
                            self.match_completed_latency(ip, &peer_snapshot)
                        {
                            info!("BLOCK: [{}] [COMPLETED LATENCY: {}]", ip, latency);
                            BlockStatus::BlockByCompletedLatency(latency)
                        } else if let BlockStatus::BlockByUploadDifference(percent) =
                            self.match_upload_data_block(ip, &peer_snapshot, &task)
                        {
                            info!(
                                "BLOCK: [{}] [UPLOAD DIFFERENCE: {:.2}%]",
                                ip,
                                percent * 100.0
                            );
                            BlockStatus::BlockByUploadDifference(percent)
                        } else {
                            BlockStatus::Unblocked
                        };

                    match block_status {
                        BlockStatus::AlreadyBlocked(_) => (),
                        BlockStatus::Unblocked => self.take_snapshot(ip, &peer_snapshot),
                        _ => {
                            peers.push(ip);
                            self.register_block(ip, &block_status);
                        }
                    }
                })
        }

        // Clean the cache on very invocation
        self.clean_cache();

        Ok(peers)
    }

    /// Get the list of active BitTorrent tasks
    async fn get_active_bittorrent_tasks(&self) -> Result<Vec<TaskStatus>> {
        Ok(self
            .client
            .tell_active()
            .await?
            .iter()
            .filter(|task| task.seeder.is_some()) // 'seeder' is only in BitTorrent task
            .cloned()
            .collect())
    }

    /// Check if the peer is already blocked
    fn match_already_blocked(&self, ip: IpAddr) -> BlockStatus {
        if let Some((status, t)) = self.cache.borrow().blocklist.get(&ip) {
            if timestamp() - t < self.option.peer_disconnect_latency as u64 {
                let s = match status {
                    BlockStatus::EmptyPeerId => "EmptyPeerId",
                    BlockStatus::IllegalBitfield => "EmptyBitfield",
                    BlockStatus::BlockByPeerId(_) => "BlockByPeerId",
                    BlockStatus::BlockByRewind(_, _) => "BlockByRewind",
                    BlockStatus::BlockByUploadDifference(_) => "BlockByUploadDifference",
                    BlockStatus::BlockByCompletedLatency(_) => "BlockByCompletedLatency",
                    _ => "",
                };
                return BlockStatus::AlreadyBlocked(s.to_owned());
            }
        }
        BlockStatus::Unblocked
    }

    fn match_empty_peer_id(&self, peer_id: &str) -> BlockStatus {
        // Mark peer_id full of '\0' as empty
        match peer_id.is_empty() || peer_id == "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" {
            true => BlockStatus::EmptyPeerId,
            false => BlockStatus::Unblocked,
        }
    }

    /// Check if the peer should be blocked based on the peer ID
    fn match_peer_id_block(&self, peer_id: &str) -> BlockStatus {
        match match_rule(peer_id, &self.rule.peer_id_block_rules) {
            true => BlockStatus::BlockByPeerId(peer_id.get(..8).unwrap_or("TOOSHORT").to_string()),
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
    fn match_rewind_block(&self, ip: IpAddr, peer: &PeerSnapshot) -> BlockStatus {
        debug!(
            "PEER DETAIL: [{}], BITFIELD: [{:.20}], PERCENTAGE: [{:.2}%]",
            ip,
            peer.bitfield,
            peer.percentage * 100.0
        );
        if let Some((snapshots, _)) = self.cache.borrow().peer_snapshots.get(&ip) {
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

    /// Check if the peer should be blocked based on the download completion to zero upload speed latency
    fn match_completed_latency(&self, ip: IpAddr, peer: &PeerSnapshot) -> BlockStatus {
        if let Some((snapshot, _)) = self.cache.borrow().peer_snapshots.get(&ip) {
            if peer.percentage == 1.0 && !snapshot.is_empty() {
                let latency = match peer.upload_speed {
                    0 => snapshot
                        .iter()
                        .position(|s| s.upload_speed == 0)
                        .unwrap_or(snapshot.len()),
                    _ => snapshot.len() + 1,
                } as u32
                    * self.option.sampling_interval;

                debug!("PEER DETAIL: [{}], COMPLETED LATENCY: [{}]", ip, latency);
                if latency > self.rule.max_latency_completed_to_zero {
                    return BlockStatus::BlockByCompletedLatency(latency);
                }
            }
        }
        BlockStatus::Unblocked
    }

    /// Check if the peer should be blocked based on the estimated upload size
    fn match_upload_data_block(
        &self,
        ip: IpAddr,
        peer: &PeerSnapshot,
        task: &TaskStatus,
    ) -> BlockStatus {
        if let Some((snapshots, _)) = self.cache.borrow().peer_snapshots.get(&ip) {
            if snapshots.len() == self.option.sampling_count as usize {
                let estimated_upload: u64 =
                    snapshots.iter().map(|peer| peer.upload_speed).sum::<u64>()
                        * self.option.sampling_interval as u64;
                debug!(
                    "PEER DETAIL: [{}], ESTIMATED UPLOAD: [{}]",
                    ip, estimated_upload
                );

                if estimated_upload > task.piece_length {
                    let peer_download =
                        // Calculate the number of pieces downloaded by the peer
                        rewind_pieces(&peer.bitfield, &snapshots.front().unwrap().bitfield) as u64
                            * task.piece_length;
                    debug!("PEER DETAIL: [{}], PEER DOWNLOAD: [{}]", ip, peer_download);

                    let diff =
                        (estimated_upload as f64 - peer_download as f64) / estimated_upload as f64;
                    debug!("PEER DETAIL: [{}], DIFFERENCE: [{}]", ip, diff);

                    if diff > self.rule.max_upload_difference {
                        return BlockStatus::BlockByUploadDifference(diff);
                    }
                }
            }
        }
        BlockStatus::Unblocked
    }

    fn register_block(&self, ip: IpAddr, status: &BlockStatus) {
        self.cache
            .borrow_mut()
            .blocklist
            .insert(ip, (status.clone(), timestamp()));
    }

    fn take_snapshot(&self, ip: IpAddr, peer: &PeerSnapshot) {
        self.cache
            .borrow_mut()
            .peer_snapshots
            .entry(ip)
            .and_modify(|(snapshots, t)| {
                snapshots.push_back(peer.clone());

                if snapshots.len() > self.option.sampling_count as usize {
                    snapshots.pop_front();
                }
                *t = timestamp();
            })
            .or_insert_with(|| (VecDeque::from([peer.clone()]), timestamp()));
    }

    fn clean_cache(&self) {
        self.clean_blocklist();
        self.clean_peer_snapshots();
        debug!(
            "BLOCKLIST: {}, {:?}",
            self.cache.borrow().blocklist.len(),
            self.cache.borrow().blocklist
        );
        debug!(
            "PEERSNAPSHOTS: {}, {:?}",
            self.cache.borrow().peer_snapshots.len(),
            self.cache.borrow().peer_snapshots
        );
    }

    fn clean_blocklist(&self) {
        let now = timestamp();
        self.cache
            .borrow_mut()
            .blocklist
            .retain(|_, (_, t)| now - *t < self.option.peer_disconnect_latency as u64);
    }

    fn clean_peer_snapshots(&self) {
        let now = timestamp();
        self.cache
            .borrow_mut()
            .peer_snapshots
            .retain(|_, (_, t)| now - *t < self.option.peer_snapshot_timeout as u64);
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
