use std::{collections::HashSet, net::IpAddr};

use log::debug;
use tokio::{spawn, time::interval};

use super::super::{Firewall, FwOption, Result, utils::Cidr};

/// Time interval (in seconds) for releasing expired blocked IPs
const RELEASE_INTERVAL: u64 = 15;

/// Handles the execution of IP blocking actions via Linux IPSet
///
/// The `Executor` is responsible for managing a single IPSet table,
/// adding blocked IP addresses and removing them after their blocking
/// duration has expired. It uses CIDR notation to potentially block
/// entire subnets based on the configured netmask.
pub struct Executor {
    /// Firewall session for managing blocked IPs
    firewall: Firewall,
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
    pub fn new(option: &FwOption, duration: u32) -> Result<Self> {
        let firewall = Firewall::new(option).init()?;

        // spawn a task to periodically release expired IPs
        let mut interval = interval(std::time::Duration::from_secs(RELEASE_INTERVAL));
        spawn(async move {
            loop {
                interval.tick().await;
                firewall.release(duration).iter().for_each(|ip| {
                    let set = match ip.is_ipv4() {
                        true => firewall.set_v4(),
                        false => firewall.set_v6(),
                    };
                    debug!("UPDATE IPSET [DEL] [{}] [{}].", set, ip);
                });
            }
        });

        Ok(Executor {
            firewall: Firewall::new(option).init()?,
        })
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
    pub fn update(&self, ips: &HashSet<IpAddr>) -> Result<()> {
        // Add new IPs
        ips.iter().try_for_each(|ip| {
            // Check if the IP is already blocked
            let (netmask, set) = match ip {
                IpAddr::V4(_) => (self.firewall.netmask_v4(), self.firewall.set_v4()),
                IpAddr::V6(_) => (self.firewall.netmask_v6(), self.firewall.set_v6()),
            };
            let ip = Cidr::new(*ip, netmask);
            self.firewall.block(&ip)?;
            debug!("UPDATE IPSET [ADD] [{}] [{}].", set, ip);
            Result::Ok(())
        })?;

        Ok(())
    }
}
