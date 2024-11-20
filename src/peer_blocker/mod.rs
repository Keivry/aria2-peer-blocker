mod blocker;
mod executor;
mod option;
mod rules;
mod utils;

pub use blocker::Blocker;
pub use executor::Executor;
pub use option::BlockOption;
pub use rules::{BlockRule, PeerIdRule};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
