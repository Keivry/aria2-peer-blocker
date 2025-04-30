use std::{sync::Arc, time::Duration};

use tokio::sync::RwLock;

use super::{
    super::{BlockOption, BlockRule, IPSetOption},
    Blocker,
    blocker::Cache,
};

pub struct BlockerBuilder {
    host: String,
    port: u16,
    secure: bool,
    secret: Option<String>,
    timeout: u32,
    max_retries: u32,
    rule: BlockRule,
    option: BlockOption,
    ipset: IPSetOption,
}

impl BlockerBuilder {
    pub fn new() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 6800,
            secure: false,
            secret: None,
            timeout: 60,
            max_retries: 3,
            rule: BlockRule::default(),
            option: BlockOption::default(),
            ipset: IPSetOption::default(),
        }
    }

    pub fn build(self) -> Blocker {
        let url = format!(
            "{}://{}:{}/jsonrpc",
            if self.secure { "wss" } else { "ws" },
            self.host,
            self.port
        );
        Blocker {
            url,
            secret: self.secret,
            timeout: Duration::from_secs(self.timeout as u64),
            max_retries: self.max_retries,
            client: Arc::new(RwLock::new(None)),
            rule: self.rule,
            option: self.option,
            ipset: self.ipset,
            cache: Arc::new(RwLock::new(Cache::empty())),
        }
    }

    pub fn host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    pub fn secret(mut self, secret: &Option<String>) -> Self {
        self.secret = secret.clone();
        self
    }

    pub fn timeout(mut self, timeout: u32) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn rule(mut self, rule: &BlockRule) -> Self {
        self.rule = rule.clone();
        self
    }

    pub fn option(mut self, option: &BlockOption) -> Self {
        self.option = option.clone();
        self
    }

    pub fn ipset(mut self, ipset: &IPSetOption) -> Self {
        self.ipset = ipset.clone();
        self
    }
}
