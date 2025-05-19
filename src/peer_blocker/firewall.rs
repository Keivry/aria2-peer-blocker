use std::{collections::HashMap, result::Result as StdResult, str::FromStr, sync::Arc};

use ipset::{Session, types::HashNet};
use iptables::IPTables;
use log::warn;
use parking_lot::RwLock;
use serde::Deserialize;

use super::{
    Result,
    utils::{Cidr, timestamp},
};

/// Default iptables rules for blocking IPs
const DEFAULT_IPTABLES_TABLE: &str = "raw";
const DEFAULT_IPTABLES_CHAIN: &str = "PREROUTING";
const DEFAULT_IPTABLES_RULE: &str = "-m set --match-set {ipset} src -j DROP";

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SetType {
    /// Use ipset for IP management, associated with iptables
    #[default]
    Ipset,
    /// Use nftables set for IP management, associated with nftables
    Nftset,
}

impl FromStr for SetType {
    type Err = String;

    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ipset" => Ok(SetType::Ipset),
            "nftset" => Ok(SetType::Nftset),
            _ => Err(format!("Invalid set type: {}", s)),
        }
    }
}

/// Configuration options for IP set management
#[derive(Clone, Debug, Deserialize)]
pub struct SetOption {
    /// Flush IPSet tables on program initialization
    /// default is true
    #[serde(default = "SetOption::default_flush")]
    pub flush: bool,

    /// IP set type, only used when firewall type is "none"
    /// otherwise use firewall associated set type
    #[serde(default)]
    pub set_type: SetType,

    /// IP set name for IPv4 addresses
    /// default is "PeerBlock"
    #[serde(default = "SetOption::default_set_v4")]
    pub set_v4: String,

    /// Netmask for IPv4 addresses (CIDR notation)
    /// default is 32
    #[serde(default = "SetOption::default_netmask_v4")]
    pub netmask_v4: u8,

    /// IP set name for IPv6 addresses
    /// default is "PeerBlockv6"
    #[serde(default = "SetOption::default_set_v6")]
    pub set_v6: String,

    /// Netmask for IPv6 addresses (CIDR notation)
    /// default is 64
    #[serde(default = "SetOption::default_netmask_v6")]
    pub netmask_v6: u8,
}

impl SetOption {
    #[inline]
    fn default_flush() -> bool { true }

    #[inline]
    fn default_set_v4() -> String { "PeerBlock".to_string() }

    #[inline]
    fn default_netmask_v4() -> u8 { 32 }

    #[inline]
    fn default_set_v6() -> String { "PeerBlockv6".to_string() }

    #[inline]
    fn default_netmask_v6() -> u8 { 64 }
}

impl Default for SetOption {
    fn default() -> Self {
        SetOption {
            flush: SetOption::default_flush(),
            set_type: SetType::default(),
            set_v4: SetOption::default_set_v4(),
            netmask_v4: SetOption::default_netmask_v4(),
            set_v6: SetOption::default_set_v6(),
            netmask_v6: SetOption::default_netmask_v6(),
        }
    }
}

/// Firewall type for blocking peers
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FwType {
    /// Use iptables with ipset
    Iptables,
    /// Use nftables with sets
    Nftables,
    /// No firewall rules, only manage IP sets
    #[default]
    None,
}

impl FromStr for FwType {
    type Err = String;

    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "iptables" => Ok(FwType::Iptables),
            "nftables" => Ok(FwType::Nftables),
            "none" => Ok(FwType::None),
            _ => Err(format!("Invalid firewall type: {}", s)),
        }
    }
}

/// Configuration options for Linux firewall integration
#[derive(Clone, Debug, Default, Deserialize)]
pub struct FwOption {
    /// Specify the firewall type to use, Iptables/Nftables or None
    /// if None, automatically setting the firewall rules is disabled
    /// and only the ipset/nftset IP management is used
    #[serde(default, rename = "type")]
    pub fw_type: FwType,

    /// Enable IPv6 support
    #[serde(default = "FwOption::default_ipv6")]
    pub ipv6: bool,

    #[serde(flatten)]
    pub set_option: SetOption,
}

impl FwOption {
    #[inline]
    fn default_ipv6() -> bool { true }
}

pub struct Iptables {
    /// IPTables session for IPv4
    pub v4: IPTables,
    /// IPTables session for IPv6
    pub v6: Option<IPTables>,
}

pub struct IPSet {
    /// IPSet session for IPv4
    pub v4: Arc<RwLock<Session<HashNet>>>,
    /// IPSet session for IPv6
    pub v6: Option<Arc<RwLock<Session<HashNet>>>>,
}

/// NFTables
pub struct Nftables {}

/// Firewall manager for handling IP blocking
pub struct Firewall {
    /// Firewall options
    option: Arc<FwOption>,
    /// Map of blocked IP addresses and their block timestamps
    ips: Arc<RwLock<HashMap<Cidr, u64>>>,
    /// IPTables session
    ipt: Option<Arc<Iptables>>,
    /// IPTables session
    ipset: Option<Arc<IPSet>>,
    /// NFTables session
    __nft: Option<Nftables>,
}

impl Firewall {
    pub fn new(option: &FwOption) -> Self {
        Firewall {
            option: Arc::new(option.clone()),
            ips: Arc::new(RwLock::new(HashMap::new())),
            ipt: None,
            ipset: None,
            __nft: None,
        }
    }

    fn init_iptables(&mut self) -> Result<&mut Self> {
        assert!(
            self.option.fw_type == FwType::Iptables,
            "Should not initialize iptables session for non-iptables firewall"
        );
        assert!(self.ipt.is_none(), "Iptables session already initialized");

        let v4 = iptables::new(false)
            .map_err(|e| format!("Failed to initialize IPv4 iptables: {}", e))?;

        let v6 = if self.option.ipv6 {
            Some(
                iptables::new(true)
                    .map_err(|e| format!("Failed to initialize IPv6 iptables: {}", e))?,
            )
        } else {
            None
        };

        self.ipt = Some(Arc::new(Iptables { v4, v6 }));

        Ok(self)
    }

    fn init_ipsets(&mut self) -> Result<&mut Self> {
        assert!(
            self.option.fw_type != FwType::Nftables,
            "Using ipset with nftables is not supported"
        );
        assert!(
            self.option.set_option.set_type == SetType::Ipset,
            "Should not initialize ipset session for non-ipset set type"
        );
        assert!(self.ipset.is_none(), "IPSet session already initialized");

        let v4 = Arc::new(RwLock::new(Session::<HashNet>::new(
            self.option.set_option.set_v4.clone(),
        )));
        let v6 = if self.option.ipv6 {
            Some(Arc::new(RwLock::new(Session::<HashNet>::new(
                self.option.set_option.set_v6.clone(),
            ))))
        } else {
            None
        };

        self.ipset = Some(Arc::new(IPSet { v4, v6 }));

        Ok(self)
    }

    fn create_iptables_rules(&self) -> Result<&Self> {
        assert!(
            self.option.fw_type == FwType::Iptables,
            "Should not create iptables rules for non-iptables firewall"
        );
        assert!(self.ipt.is_some(), "IPTables session not initialized");

        let iptables_v4 = &self.ipt.as_ref().unwrap().v4;
        // Check & add iptables rules
        if !iptables_v4
            .exists(
                DEFAULT_IPTABLES_TABLE,
                DEFAULT_IPTABLES_CHAIN,
                DEFAULT_IPTABLES_CHAIN,
            )
            .unwrap()
        {
            iptables_v4
                .insert(
                    DEFAULT_IPTABLES_TABLE,
                    DEFAULT_IPTABLES_CHAIN,
                    &DEFAULT_IPTABLES_RULE.replace("{ipset}", &self.option.set_option.set_v4),
                    0,
                )
                .unwrap();
        }

        if self.option.ipv6 {
            let iptables_v6 = self.ipt.as_ref().unwrap().v6.as_ref().unwrap();

            // Check & add ip6tables rules
            if !iptables_v6
                .exists(
                    DEFAULT_IPTABLES_TABLE,
                    DEFAULT_IPTABLES_CHAIN,
                    DEFAULT_IPTABLES_CHAIN,
                )
                .map_err(|_| false)
                .unwrap()
            {
                iptables_v6
                    .insert(
                        DEFAULT_IPTABLES_TABLE,
                        DEFAULT_IPTABLES_CHAIN,
                        &DEFAULT_IPTABLES_RULE.replace("{ipset}", &self.option.set_option.set_v6),
                        0,
                    )
                    .map_err(|e| format!("Create iptables rules failed: {}", e))?;
            }
        }

        Ok(self)
    }

    fn init_nftables(&mut self) -> Result<&mut Self> {
        // TODO: Implement nftables session initialization
        unimplemented!()
    }

    fn init_nftset(&mut self) -> Result<&mut Self> {
        // TODO: Implement nftset session initialization
        unimplemented!()
    }

    fn create_nftables_rules(&self) -> Result<&Self> {
        // TODO: Implement nftables rules creation
        unimplemented!()
    }

    /// Initialize the firewall session, creating necessary tables and chains
    pub fn init(mut self) -> Result<Self> {
        match self.option.fw_type {
            FwType::Iptables => {
                self.init_iptables()?
                    .init_ipsets()?
                    .create_iptables_rules()?;
            }
            FwType::Nftables => {
                self.init_nftables()?
                    .init_nftset()?
                    .create_nftables_rules()?;
            }
            FwType::None => {
                // No firewall rules, only manage sets
                match self.option.set_option.set_type {
                    SetType::Ipset => {
                        self.init_ipsets()?;
                    }
                    SetType::Nftset => {
                        self.init_nftset()?;
                    }
                }
            }
        }

        if self.option.set_option.flush {
            self.flush()?;
        }

        Ok(self)
    }

    pub fn set_v4(&self) -> &str { &self.option.set_option.set_v4 }

    pub fn set_v6(&self) -> &str { &self.option.set_option.set_v6 }

    pub fn netmask_v4(&self) -> u8 { self.option.set_option.netmask_v4 }

    pub fn netmask_v6(&self) -> u8 { self.option.set_option.netmask_v6 }

    fn flush_ipset(&self) -> Result<&Self> {
        if let Some(ipset) = &self.ipset {
            ipset.v4.write().flush()?;
            if self.option.ipv6 {
                ipset.v6.as_ref().unwrap().write().flush()?;
            }
        }
        Ok(self)
    }

    fn flush_nftset(&self) -> Result<&Self> {
        // TODO:
        todo!("Implement flush for nftset");
    }

    /// Flush the IPSet/Nftset
    pub fn flush(&self) -> Result<&Self> {
        match self.option.set_option.set_type {
            SetType::Ipset => self.flush_ipset(),
            SetType::Nftset => self.flush_nftset(),
        }
    }

    /// Add an IP to the IPSet
    fn ipset_add(&self, ip: &Cidr) -> Result<&Self> {
        let ipset = self.ipset.as_ref().unwrap();

        if ip.is_ipv4() {
            ipset.v4.write().add(ip, &[])?;
        } else if let Some(v6) = &ipset.v6 {
            v6.write().add(ip, &[])?;
        } else {
            return Err("IPv6 is not supported".into());
        }
        Ok(self)
    }

    /// Remove an IP from the IPSet
    fn ipset_del(&self, ip: &Cidr) -> Result<&Self> {
        let ipset = self.ipset.as_ref().unwrap();

        if ip.is_ipv4() {
            ipset.v4.write().del(ip)?;
        } else if let Some(v6) = &ipset.v6 {
            v6.write().del(ip)?;
        } else {
            return Err("IPv6 is not supported".into());
        }
        Ok(self)
    }

    fn nftset_add(&self, _ip: &Cidr) -> Result<&Self> {
        // TODO: Implement nftset add
        unimplemented!()
    }

    fn nftset_del(&self, _ip: &Cidr) -> Result<&Self> {
        // TODO: Implement nftset delete
        unimplemented!()
    }

    pub fn block(&self, ip: &Cidr) -> Result<&Self> {
        // Add IP to the IPSet/Nftset
        match self.option.set_option.set_type {
            SetType::Ipset => self.ipset_add(ip)?,
            SetType::Nftset => self.nftset_add(ip)?,
        };

        // Store the IP and its block timestamp
        self.ips.write().insert(ip.clone(), timestamp());

        Ok(self)
    }

    pub fn unblock(&self, ip: &Cidr) -> Result<&Self> {
        // Remove IP from the IPSet/Nftset
        match self.option.set_option.set_type {
            SetType::Ipset => self.ipset_del(ip)?,
            SetType::Nftset => self.nftset_del(ip)?,
        };

        // Remove the IP from the stored map
        self.ips.write().remove(ip);

        Ok(self)
    }

    /// Release IPs that have been blocked for a specified duration
    /// Returns a map of released IPs grouped by their set names
    pub fn release(&self, duration: u32) -> Vec<Cidr> {
        let mut released = Vec::new();
        let mut to_unblock = Vec::new();

        // Get all expired IPs
        {
            let now = timestamp();
            for (ip, timestamp) in self.ips.read().iter() {
                if now - timestamp > duration as u64 {
                    // Add to released IPs
                    to_unblock.push(ip.clone());
                }
            }
        }

        // Unblock expired IPs
        for ip in &to_unblock {
            if let Err(e) = self.unblock(ip) {
                warn!("Failed to unblock IP {}: {}", ip, e);
            } else {
                released.push(ip.clone());
            }
        }

        released
    }
}
