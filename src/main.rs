mod config;
mod peer_blocker;

use std::{io::Write, str::FromStr};

use chrono::Local;
use clap::Parser;
use colored::{Color, Colorize};
use config::Config;
use log::{LevelFilter, debug};
use peer_blocker::Blocker;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<String>,

    /// Enable timestamp in logs (overrides config file setting)
    #[arg(short, long)]
    timestamp: bool,
}

#[tokio::main]
async fn main() {
    // Parse CLI args
    let cli = Cli::parse();

    // Load configuration
    let mut config = match cli.config {
        Some(path) => Config::load(&path).expect("Failed to load configuration file"),
        None => Config::default(),
    };

    // CLI timestamp option overrides config file setting
    config.log.timestamp = cli.timestamp || config.log.timestamp;

    // Initialize logger
    init_logger(
        config.log.timestamp,
        LevelFilter::from_str(&config.log.level).unwrap(),
    );
    debug!("LOADED CONFIGURATION: {:?}", &config);

    Blocker::builder()
        .host(&config.aria2_rpc.host)
        .port(config.aria2_rpc.port)
        .secure(config.aria2_rpc.secure)
        .secret(&config.aria2_rpc.secret)
        .timeout(config.aria2_rpc.timeout)
        .max_retries(config.aria2_rpc.max_retries)
        .rule(&config.rules)
        .option(&config.option)
        .fw_option(&config.firewall)
        .build()
        .start()
        .await;
}

/// Custom logger initialization, with optional timestamp
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
