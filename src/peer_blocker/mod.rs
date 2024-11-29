mod blocker;
mod ipset;
mod option;
mod rules;
mod utils;

pub use blocker::Blocker;
pub use ipset::IPSetOption;
pub use option::BlockOption;
pub use rules::BlockRule;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
