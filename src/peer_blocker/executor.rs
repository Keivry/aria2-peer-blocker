use super::utils::timestamp;

use anyhow::Result;
use ipset::{types::HashIp, Session};
use log::info;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub struct Executor {
    pub ipset: String,
    pub ips: HashMap<IpAddr, u64>,
    pub duration: u32,
    session: Session<HashIp>,
}

impl Executor {
    pub fn new(ipset: &str, duration: u32) -> Self {
        Executor {
            ipset: ipset.to_owned(),
            ips: HashMap::new(),
            duration,
            session: Session::<HashIp>::new(ipset.to_owned()),
        }
    }

    pub fn update(&mut self, ips: &HashSet<IpAddr>) -> Result<()> {
        let now = timestamp();

        // Add new IPs
        ips.iter().try_for_each(|ip| {
            self.session.add(*ip, &[])?;
            self.ips.insert(*ip, now);
            info!("Added IP [{}] to Ipset [{}].", ip, self.ipset);
            anyhow::Ok(())
        })?;

        // Clean old IPs
        self.ips.retain(|ip, &mut timestamp| {
            if now - timestamp > self.duration as u64 {
                self.session.del(*ip).ok();
                info!("Removed IP [{}] from Ipset [{}].", ip, self.ipset);
                false
            } else {
                true
            }
        });

        Ok(())
    }
}
