use super::{
    utils::{timestamp, Cidr},
    Result,
};

use ipset::{types::HashNet, Session};
use log::info;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub struct Executor {
    pub ipset: String,
    pub netmask: u8,
    pub duration: u32,
    pub ips: HashMap<Cidr, u64>,
    session: Session<HashNet>,
}

impl Executor {
    pub fn new(ipset: &str, netmask: u8, duration: u32, flush: bool) -> Self {
        let mut session = Session::<HashNet>::new(ipset.to_owned());

        if flush {
            // Clear all existing IPs on initialization
            session.flush().ok();
        }

        Executor {
            ipset: ipset.to_owned(),
            netmask,
            duration,
            ips: HashMap::new(),
            session,
        }
    }

    pub fn update(&mut self, ips: &HashSet<IpAddr>) -> Result<()> {
        let now = timestamp();

        // Add new IPs
        ips.iter().try_for_each(|ip| {
            let net = Cidr::new(*ip, self.netmask);
            self.session.add(&net, &[])?;
            self.ips.insert(net.clone(), now);
            info!("UPDATE IPSET [ADD] [{}] [{}].", self.ipset, net);
            Result::Ok(())
        })?;

        // Clean old IPs
        self.ips.retain(|net, &mut timestamp| {
            if now - timestamp > self.duration as u64 {
                self.session.del(net).ok();
                info!("UPDATE IPSET [DEL] [{}] [{}].", self.ipset, net);
                false
            } else {
                true
            }
        });

        Ok(())
    }
}
