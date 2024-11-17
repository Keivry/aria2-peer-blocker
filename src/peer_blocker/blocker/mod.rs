mod _impl_;

use super::{option::BlockOption, rules::BlockRule};

use aria2_ws::Client;

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::rc::Rc;

/// PeerBlocker is a tool for blocking malicious peers in aria2
pub struct PeerBlocker {
    /// The websocket rpc client for interacting with the aria2 server
    pub(super) client: Client,
    /// The rules for blocking peers
    pub(super) rule: BlockRule,
    /// The options for blocking peers
    pub(super) option: BlockOption,
    /// The cache for storing the blocklist and peer snapshots
    pub(super) cache: Rc<RefCell<Cache>>,
}

/// The status of a peer being blocked
#[derive(Debug, Clone, PartialEq)]
pub(super) enum BlockStatus {
    Unblocked,                    // Not blocked
    EmptyPeerId,                  // Empty peer ID
    EmptyBitfield,                // Empty bitfield
    BlockByPeerId(String),        // Blocked by peer ID with peer id prefix
    BlockByRewind(u32, f64),      // Blocked by rewinding pieces count and percentage
    BlockByUploadDifference(f64), // Blocked by upload progress difference
    AlreadyBlocked(String),       // Already blocked
}

/// PeerSnapshot stores the snapshot of a peer's download progress
#[derive(Debug, Clone)]
pub(super) struct PeerSnapshot {
    pub(super) bitfield: String,  // The peer's bitfield
    pub(super) upload_speed: u64, // The client's upload speed to the peer
}

/// Cache stores the blocklist and peer snapshots
#[derive(Default)]
pub(super) struct Cache {
    /// The blocklist stores the blocked IP, block status and the timestamp when they were blocked
    /// Used for checking if the peer is already blocked before aria2 disconnects it
    /// The IP addresses will be removed from the blocklist after the peer_disconnect_latency duration
    pub(super) blocklist: HashMap<IpAddr, (BlockStatus, u64)>,
    /// The peer_snapshots stores the snapshots of the peer's download progress,
    /// and the timestamp when the last snapshot was taken
    /// Used for checking if the peer is rewinding or uploading too much data
    /// The snapshots will be removed after the peer_snapshot_timeout duration
    pub(super) peer_snapshots: HashMap<IpAddr, (VecDeque<PeerSnapshot>, u64)>,
}
