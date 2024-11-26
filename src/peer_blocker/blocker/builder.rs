use super::{
    super::{BlockOption, BlockRule, Result},
    Blocker,
};

use aria2_ws::Client;

use std::rc::Rc;

#[derive(Default)]
pub struct BlockerBuilder {
    host: String,
    port: u16,
    secure: bool,
    secret: Option<String>,
    rule: BlockRule,
    option: BlockOption,
}

impl BlockerBuilder {
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
    pub fn rule(mut self, rule: &BlockRule) -> Self {
        self.rule = rule.clone();
        self
    }
    pub fn option(mut self, option: &BlockOption) -> Self {
        self.option = option.clone();
        self
    }
    pub async fn build(self) -> Result<Blocker> {
        let url = format!(
            "{}://{}:{}/jsonrpc",
            if self.secure { "wss" } else { "ws" },
            self.host,
            self.port
        );
        Ok(Blocker {
            client: Client::connect(&url, self.secret.as_deref()).await?,
            rule: self.rule,
            option: self.option,
            cache: Rc::default(),
        })
    }
}
