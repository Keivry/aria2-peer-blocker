use chrono::Local;

pub fn timestamp() -> u64 {
    Local::now().timestamp() as u64
}
