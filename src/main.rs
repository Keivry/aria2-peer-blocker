mod config;
use config::{Config, Rule, RuleMethod};

mod blocker;

use log::{error, info};
use serde_json::from_str;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::time::Duration;
use tokio::time::sleep;

// 从配置文件加载 Config
fn load_config(filename: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let config_data = fs::read_to_string(filename)?;
    let config: Config = from_str(&config_data)?;
    Ok(config)
}

// 读取 `xt_recent` 表中的所有 IP 到 HashSet 中，避免重复读取文件
fn load_recent_ips(table: &str) -> io::Result<HashSet<String>> {
    let path = format!("/proc/net/xt_recent/{}", table);
    let file = fs::File::open(&path)?;
    let reader = io::BufReader::new(file);

    let mut ips = HashSet::new();
    reader.lines().try_for_each(|line| {
        let line = line?;
        if let Some(ip) = line.split_whitespace().next() {
            ips.insert(ip.to_string());
        }
        io::Result::Ok(())
    })?;

    Ok(ips)
}

// 批量写入 IP 地址到 `xt_recent` 表，避免重复写入和频繁文件操作
fn write_iptables_recent(ips: HashSet<String>, table: &str) {
    let recent_ips = match load_recent_ips(table) {
        Ok(ips) => ips,
        Err(e) => {
            error!("Failed to load recent IPs from {}: {:?}", table, e);
            return;
        }
    };
    let path = format!("/proc/net/xt_recent/{}", table);
    match OpenOptions::new().write(true).open(&path) {
        Ok(mut file) => {
            for ip in ips {
                if !recent_ips.contains(&ip) {
                    if let Err(e) = writeln!(file, "+{}", ip) {
                        error!("Failed to add {} to {}: {:?}", ip, table, e);
                    } else {
                        info!("Successfully added {} to {}.", ip, table);
                    }
                } else {
                    info!("IP: {} already in {}.", ip, table);
                }
            }
        }
        Err(e) => error!("Failed to open file {}: {:?}", path, e),
    }
}

#[tokio::main]
async fn main() {
    // 初始化日志记录
    //env_logger::init();

    // 加载配置文件
    let config = load_config("config.json").expect("Failed to load configuration.");
    let scan_interval = Duration::from_secs(config.scan_interval);
    // let exception_interval = Duration::from_secs(config.exception_interval);

    info!("Loaded config: {:?}", config);

    loop {
        info!("Aria2 RPC URL: {}", config.aria2_rpc_url);

        // 示例：检查一个 peer_id 是否在禁止列表中
        let peer_id = "-xm123456";
        if is_banned(peer_id, &config.block_peer_id_rules) {
            info!("Peer ID {} is banned", peer_id);
        }

        // 示例：更新 xt_recent 表中的 IP
        let ipv4: HashSet<String> = vec!["192.168.1.1".to_string()].into_iter().collect();
        let ipv6: HashSet<String> = vec!["2001:db8::1".to_string()].into_iter().collect();
        write_iptables_recent(ipv4, "BTBANNED");
        write_iptables_recent(ipv6, "BTBANNEDv6");

        sleep(scan_interval).await;
    }
}
