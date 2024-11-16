mod config;
use config::Config;

mod peer_blocker;
use peer_blocker::{BlockOption, BlockRule, Executor, PeerBlocker};

use chrono::Local;
use clap::Parser;
use log::{debug, error, LevelFilter};
use tokio::time::sleep;

use std::{collections::HashSet, net::IpAddr, rc::Rc, str::FromStr, time::Duration};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// path to the configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Load configuration
    let config = Rc::new(Config::load_config(&cli.config).expect("Failed to load configuration."));

    // Initialize logger
    env_logger::Builder::new()
        .format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "[{}] [{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .filter_level(LevelFilter::from_str(&config.log_level).unwrap())
        .target(env_logger::Target::Stdout)
        .init();

    debug!("Loaded config: {:?}", Rc::clone(&config));

    let interval = Duration::from_secs(config.interval as u64);
    let exception_interval = Duration::from_secs(config.exception_interval as u64);

    // Initialize PeerBlocker
    let block_rule = BlockRule::builder()
        .max_rewind_pieces(config.max_rewind_pieces)
        .max_rewind_percent(config.max_rewind_percent)
        .max_difference(config.max_difference)
        .peer_id_block_rules(config.peer_id_rules.clone())
        .build();
    let block_option = BlockOption::builder()
        .sampling_count(config.sampling_count)
        .sampling_interval(config.interval)
        .peer_snapshot_timeout(config.peer_snapshot_timeout)
        .peer_disconnect_latency(config.peer_disconnect_latency)
        .build();
    let blocker = loop {
        match PeerBlocker::builder()
            .host(&config.aria2_rpc_host)
            .port(config.aria2_rpc_port)
            .secure(config.aria2_rpc_secure)
            .secret(&config.aria2_rpc_secret)
            .rule(&block_rule)
            .option(&block_option)
            .build()
            .await
        {
            Ok(blocker) => break blocker,
            Err(e) => {
                error!("Failed to initialize PeerBlocker: {:?}", e);
                sleep(exception_interval).await;
            }
        }
    };

    // Initialize Executor
    let mut executor_v4 = Executor::new(&config.ipset_v4, config.block_duration);
    let mut executor_v6 = Executor::new(&config.ipset_v6, config.block_duration);

    // Get blocked peers and write to ipset
    loop {
        let peers = loop {
            match blocker.get_blocked_peers().await {
                Ok(peers) => break peers,
                Err(e) => {
                    error!("Failed to get blocked peers: {:?}", e);
                    sleep(exception_interval).await;
                }
            }
        };
        debug!("Blocked peers: {:?}", peers);

        // Split ipv4 and ipv6 peers
        let (ipv4, ipv6): (HashSet<IpAddr>, HashSet<IpAddr>) =
            peers.into_iter().partition(|ip| ip.is_ipv4());

        // Update ipset
        executor_v4
            .update(&ipv4)
            .unwrap_or_else(|_| error!("Failed to update ipset [{}]!", config.ipset_v4));
        executor_v6
            .update(&ipv6)
            .unwrap_or_else(|_| error!("Failed to update ipset [{}]!", config.ipset_v6));

        sleep(interval).await
    }
}
