use aria2_ws::Client;

use anyhow::Result;

use crate::config::{Config, Rule, RuleMethod};

use serde_json::Value;

use std::collections::HashMap;
use std::error::Error;

use log::{error, info};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;
use tokio::time::sleep;

pub struct TaskStatus {
    pub gid: String,
    pub piece_length: u64,
    pub num_pieces: u64,
}

pub struct PeerInfo {
    pub ip: IpAddr,
    pub peer_id: Option<String>,
    pub bitfield: String,
}

pub struct PeerBlocker {
    config: Rc<Config>,

    client: Client,

    // Hash map for peer ip address ,bitfield and download_speed
    peer_history: HashMap<IpAddr, Vec<PeerInfo>>,
}

impl PeerBlocker {
    pub async fn new(config: Rc<Config>) -> Result<Self> {
        let url = format!(
            "{}://{}:{}/jsonrpc",
            if config.rpc_secure { "wss" } else { "ws" },
            config.rpc_host,
            config.rpc_port
        );
        Ok(Self {
            config: config.clone(),
            client: Client::connect(&url, config.rpc_secret.as_deref()).await?,
            peer_history: HashMap::new(),
        })
    }

    async fn get_active_bittorrent_tasks(&self) -> Result<Vec<TaskStatus>> {
        Ok(self
            .client
            .custom_tell_active(Some(vec![
                "gid".to_owned(),
                "seader".to_owned(),
                "pieceLength".to_owned(),
                "numPieces".to_owned(),
            ]))
            .await?
            .iter()
            .filter_map(|task| {
                task.get("seeder").and_then(|_| {
                    task.get("gid").and_then(|gid| {
                        task.get("pieceLength").and_then(|piece_length| {
                            piece_length.as_u64().and_then(|piece_length| {
                                task.get("numPieces").and_then(|num_pieces| {
                                    num_pieces.as_u64().map(|num_pieces| TaskStatus {
                                        gid: gid.to_string(),
                                        piece_length,
                                        num_pieces,
                                    })
                                })
                            })
                        })
                    })
                })
            })
            .collect())
    }

    // fn check_bitfield(&mut self, ip: IpAddr, bitfield: &str, download_speed: u64) -> bool {
    //     let shot = self.peer_history.entry(ip).or_insert_with(Vec::new);
    //     shot.push((bitfield.to_string(), download_speed));
    //     if shot.len() > self.config.bitfield_sampling_count as usize {
    //         shot.pop();
    //     }
    //     let mut bitfield_set = HashSet::new();
    //     for (bitfield, _) in shot.iter() {
    //         bitfield_set.insert(bitfield);
    //     }
    //     bitfield_set.len() == 1
    // }

    async fn filter_peers(&self, gid: &str) -> Result<Vec<IpAddr>> {
        self.client
            .get_peers(gid)
            .await?
            .iter()
            .filter_map(|peer| {
                peer.ip.parse().ok().map(|ip| PeerInfo {
                    ip,
                    peer_id: Some(peer.peer_id),
                    bitfield: peer.bitfield,
                })
            })
            .collect()
    }

    pub async fn start(&self) {
        loop {
            let tasks = self.get_active_bittorrent_tasks().await.unwrap();
            let mut ips = HashSet::new();
            for task in tasks {
                let peer_id = task.peer_id.as_ref().map_or("", String::as_str);
                if is_banned(peer_id, &config.banned_peer_id_rules) {
                    if let Some(ip) = task.ip {
                        ips.insert(ip);
                    }
                }
            }
            write_iptables_recent(ips, "aria2")?;
            sleep(Duration::from_secs(config.scan_interval)).await;
        }
    }
}

fn is_banned(peer_id: &str, rules: &[Rule]) -> bool {
    let peer_id = peer_id.to_lowercase();
    rules.iter().any(|rule| match rule.method {
        RuleMethod::StartsWith => peer_id.starts_with(&rule.content),
        RuleMethod::Contains => peer_id.contains(&rule.content),
    })
}
