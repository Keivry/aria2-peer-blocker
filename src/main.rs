mod config;
use config::Config;

mod peer_blocker;
use peer_blocker::Blocker;

use chrono::Local;
use clap::Parser;
use colored::{Color, Colorize};
use log::{debug, LevelFilter};

use std::{io::Write, str::FromStr};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// path to the configuration file
    #[arg(short, long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() {
    // Load configuration
    let config = match Cli::parse().config {
        Some(path) => Config::load(&path).expect("Failed to load configuration file"),
        None => Config::default(),
    };

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
        .ipset(&config.ipset)
        .build()
        .start()
        .await;
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
