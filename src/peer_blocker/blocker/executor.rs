use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use ipset::{Session, types::HashNet};
use log::debug;

use super::super::{
    Result,
    utils::{Cidr, timestamp},
};

/// Handles the execution of IP blocking actions via Linux IPSet
///
/// The `Executor` is responsible for managing a single IPSet table,
/// adding blocked IP addresses and removing them after their blocking
/// duration has expired. It uses CIDR notation to potentially block
/// entire subnets based on the configured netmask.
pub struct Executor {
    /// Name of the IPSet table to manage
    pub ipset: String,

    /// Netmask to apply when blocking IPs (allows blocking entire subnets)
    /// For IPv4: 32 blocks a specific IP, lower values block larger subnets
    /// For IPv6: 128 blocks a specific IP, lower values block larger subnets
    pub netmask: u8,

    /// How long (in seconds) IPs should remain blocked before being removed
    pub duration: u32,

    /// Map of currently blocked CIDRs and their block timestamp
    pub ips: HashMap<Cidr, u64>,

    /// Active IPSet session for interacting with the kernel's IPSet subsystem
    session: Session<HashNet>,
}

impl Executor {
    /// Creates a new IPSet executor
    ///
    /// # Parameters
    ///
    /// * `ipset` - Name of the IPSet table to manage
    /// * `netmask` - Netmask to apply to blocked IPs
    /// * `duration` - How long (in seconds) IPs should remain blocked
    /// * `flush` - Whether to clear the IPSet table on initialization
    ///
    /// # Returns
    ///
    /// A new Executor instance configured to manage the specified IPSet table
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

    /// Updates the IPSet table with new blocked IPs and removes expired entries
    ///
    /// This method performs two key functions:
    /// 1. Adds any new IPs from the provided set to the IPSet table
    /// 2. Removes any IPs that have been blocked longer than the configured duration
    ///
    /// # Parameters
    ///
    /// * `ips` - Set of IP addresses that should be blocked
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the update was successful
    /// * `Err` if there was a problem interacting with the IPSet subsystem
    pub fn update(&mut self, ips: &HashSet<IpAddr>) -> Result<()> {
        let now = timestamp();

        // Add new IPs
        ips.iter().try_for_each(|ip| {
            let net = Cidr::new(*ip, self.netmask);
            self.session.add(&net, &[])?;
            self.ips.insert(net.clone(), now);
            debug!("UPDATE IPSET [ADD] [{}] [{}].", self.ipset, net);
            Result::Ok(())
        })?;

        // Clean old IPs
        self.ips.retain(|net, &mut timestamp| {
            if now - timestamp > self.duration as u64 {
                self.session.del(net).ok();
                debug!("UPDATE IPSET [DEL] [{}] [{}].", self.ipset, net);
                false
            } else {
                true
            }
        });

        Ok(())
    }
}
