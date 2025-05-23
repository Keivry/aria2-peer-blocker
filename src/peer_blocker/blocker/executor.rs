use std::{collections::HashSet, net::IpAddr, time::Duration};

use log::debug;
use tokio::{spawn, time::interval};

use super::super::{Firewall, FwOption, FwType, Result, utils::Cidr};

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
    pub fn new(option: &FwOption) -> Result<Self> {
        let firewall = Firewall::init(option.clone())?;

        match option.fw_type {
            FwType::Iptables | FwType::None => {
                let firewall = firewall.clone();
                let timeout = option.timeout;

                // spawn a task to periodically release expired IPs
                let mut interval = interval(Duration::from_secs(RELEASE_INTERVAL));
                spawn(async move {
                    loop {
                        interval.tick().await;
                        let ipset = firewall.session().ipset().unwrap();
                        ipset.release(timeout).iter().for_each(|ip| {
                            let set = match ip.is_ipv4() {
                                true => ipset.v4().name(),
                                false => ipset.v6().unwrap().name(),
                            };
                            debug!("UPDATE IPSET [DEL] [{set}] [{ip}].");
                        });
                    }
                });
            }
            FwType::Nftables => {
                // Nftables does not require a separate task for releasing expired IPs
                // as it handles this automatically based on the rules defined.
            }
        }

        Ok(Self { firewall })
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
            let netmask = match ip {
                IpAddr::V4(_) => self.firewall.netmask_v4(),
                IpAddr::V6(_) => self.firewall.netmask_v6().unwrap(),
            };
            let ip = Cidr::new(*ip, netmask);
            let set = self.firewall.block(&ip)?;
            debug!("UPDATE IPSET [ADD] [{set}] [{ip}].");
            Result::Ok(())
        })?;

        Ok(())
    }
}
