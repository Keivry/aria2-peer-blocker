mod config;
use config::Config;

mod peer_blocker;
use peer_blocker::{BlockOption, BlockRule, Blocker, Executor};

use chrono::Local;
use clap::Parser;
use colored::{Color, Colorize};
use log::{debug, error, LevelFilter};
use tokio::time::sleep;

use std::{io::Write, rc::Rc, str::FromStr, time::Duration};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// path to the configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() {
    // Load configuration
    let config =
        Rc::new(Config::load(&Cli::parse().config).expect("Failed to load configuration."));
    // Initialize logger
    init_logger(
        config.log.timestamp,
        LevelFilter::from_str(&config.log.level).unwrap(),
    );
    debug!("LOADED CONFIGURATION: {:?}", Rc::clone(&config));

    let interval = Duration::from_secs(config.option.interval as u64);
    let exception_interval = Duration::from_secs(config.option.exception_interval as u64);

    // Initialize PeerBlocker
    let block_rule = BlockRule::builder()
        .max_rewind_pieces(config.rules.max_rewind_pieces)
        .max_rewind_percent(config.rules.max_rewind_percent)
        .max_upload_difference(config.rules.max_upload_difference)
        .max_latency_completed_to_zero(config.rules.max_latency_completed_to_zero)
        .peer_id_block_rules(config.rules.peer_id_rules.clone())
        .build();
    let block_option = BlockOption::builder()
        .snapshots_count(config.option.snapshots_count)
        .interval(config.option.interval)
        .peer_snapshot_timeout(config.option.peer_snapshot_timeout)
        .peer_disconnect_latency(config.option.peer_disconnect_latency)
        .build();
    let blocker = loop {
        match Blocker::builder()
            .host(&config.aria2_rpc.host)
            .port(config.aria2_rpc.port)
            .secure(config.aria2_rpc.secure)
            .secret(&config.aria2_rpc.secret)
            .rule(&block_rule)
            .option(&block_option)
            .build()
            .await
        {
            Ok(blocker) => break blocker,
            Err(e) => {
                error!("Initialization error: {:?}", e);
                sleep(exception_interval).await;
            }
        }
    };

    // Initialize Executor
    let mut executor_v4 = Executor::new(
        &config.ipset.v4,
        config.ipset.netmask_v4,
        config.option.block_duration,
        config.ipset.flush,
    );
    let mut executor_v6 = Executor::new(
        &config.ipset.v6,
        config.ipset.netmask_v6,
        config.option.block_duration,
        config.ipset.flush,
    );

    // Get blocked peers and write to ipset
    loop {
        let (ipv4, ipv6) = loop {
            match blocker.get_blocked_peers().await {
                Ok(peers) => break peers,
                Err(e) => {
                    error!("Error querying blocked peers: {:?}", e);
                    sleep(exception_interval).await;
                }
            }
        };
        debug!("BLOCKED IPV4 PEERS: {:?}", ipv4);
        debug!("BLOCKED IPV6 PEERS: {:?}", ipv6);

        // Update ipset
        executor_v4
            .update(&ipv4)
            .unwrap_or_else(|_| error!("Error updating IPSet [{}]!", config.ipset.v4));
        executor_v6
            .update(&ipv6)
            .unwrap_or_else(|_| error!("Error updating IPSet [{}]!", config.ipset.v6));

        sleep(interval).await
    }
}

fn init_logger(timestamp: bool, level: LevelFilter) {
    env_logger::Builder::new()
        .format(move |buf, record| {
            let color = match record.level() {
                log::Level::Error => Color::Red,
                log::Level::Warn => Color::Yellow,
                log::Level::Info => Color::Green,
                log::Level::Debug => Color::Blue,
                log::Level::Trace => Color::Magenta,
            };
            let level = format!("{:5}", record.level()).color(color);
            if timestamp {
                writeln!(
                    buf,
                    "[{} {}] {}",
                    Local::now().format("%Y-%m-%d %H:%M:%S"),
                    level,
                    record.args()
                )
            } else {
                writeln!(buf, "[{}] {}", level, record.args())
            }
        })
        .filter_module("aria2_peer_blocker", level)
        .init();
}
