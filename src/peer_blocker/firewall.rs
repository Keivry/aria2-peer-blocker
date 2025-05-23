use std::{
    borrow::Cow,
    collections::HashMap,
    result::Result as StdResult,
    str::FromStr,
    sync::Arc,
};

use ipset::{Session, types::HashNet};
use iptables::IPTables;
use log::warn;
use nftables::{batch::Batch, expr, helper, schema, stmt, types};
use parking_lot::RwLock;
use serde::Deserialize;

use super::{
    Result,
    utils::{Cidr, timestamp},
};

// Default options for managed iptables firewall
const DEFAULT_IPTABLES_TABLE: &str = "raw";
const DEFAULT_IPTABLES_CHAIN_HOOK: &str = "PREROUTING";
const DEFAULT_IPTABLES_CHAIN: &str = "aria2-peer-block-chain";
const DEFAULT_IPTABLES_RULE: &str = "-m set --match-set {ipset} src -j DROP";

// Default options for managed nftables firewall
const DEFAULT_NFTABLES_TABLE: &str = "aria2-peer-block-table";
const DEFAULT_NFTABLES_CHAIN: &str = "aria2-peer-block-chain";
const DEFAULT_NFTABLES_CHAIN_TYPE: types::NfChainType = types::NfChainType::Filter;
const DEFAULT_NFTABLES_CHAIN_HOOK: types::NfHook = types::NfHook::Prerouting;
const DEFAULT_NFTABLES_CHAIN_PRIORITY: i32 = -300; // NF_IP_PRI_RAW
const DEFAULT_NFTABLES_CHAIN_POLICY: types::NfChainPolicy = types::NfChainPolicy::Accept;
const DEFAULT_NFTABLES_SET_TYPE: schema::SetTypeValue =
    schema::SetTypeValue::Concatenated(Cow::Borrowed(&[
        schema::SetType::Ipv4Addr,
        schema::SetType::Ipv6Addr,
    ]));

/// Configuration options for IP set management
#[derive(Clone, Debug, Deserialize)]
pub struct IpSetOption {
    /// Ipset name for IPv4 addresses
    /// default is "aria2-peer-blocker-set_v4"
    #[serde(default = "IpSetOption::default_set_v4")]
    pub set_v4: String,

    /// Ipset name for IPv6 addresses
    /// default is "aria2-peer-blocker-set_v6"
    #[serde(default = "IpSetOption::default_set_v6")]
    pub set_v6: Option<String>,
}

impl IpSetOption {
    #[inline]
    fn default_set_v4() -> String { "aria2-peer-blocker-set_v4".to_string() }

    #[inline]
    fn default_set_v6() -> Option<String> { Some("aria2-peer-blocker-set_v6".to_string()) }
}

impl Default for IpSetOption {
    fn default() -> Self {
        IpSetOption {
            set_v4: IpSetOption::default_set_v4(),
            set_v6: IpSetOption::default_set_v6(),
        }
    }
}

/// Configuration options for IP set management
#[derive(Clone, Debug, Deserialize)]
pub struct NftSetOption {
    /// Nftables set name, default is "aria2-peer-blocker-set"
    #[serde(default = "NftSetOption::default_set")]
    pub set: String,
}

impl NftSetOption {
    #[inline]
    fn default_set() -> String { "aria2-peer-blocker-set".to_string() }
}

impl Default for NftSetOption {
    fn default() -> Self {
        NftSetOption {
            set: NftSetOption::default_set(),
        }
    }
}

/// Firewall type for blocking peers
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FwType {
    /// Unmanaged firewall
    #[default]
    None,

    /// Managed iptables firewall with ipset
    Iptables,

    /// Managed nftables firewall with nftset
    Nftables,
}

impl FromStr for FwType {
    type Err = String;

    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(FwType::None),
            "iptables" => Ok(FwType::Iptables),
            "nftables" => Ok(FwType::Nftables),
            _ => Err(format!("Invalid firewall type: {s}")),
        }
    }
}

/// Configuration options for Linux firewall integration
#[derive(Clone, Debug, Deserialize)]
pub struct FwOption {
    /// Specify the firewall type to use, None or Iptables/Nftables
    /// If None, firewall is unmanaged by this program, blocked IPs
    /// will be added to ipset with specified name, users can manually
    /// create iptables rules to block IPs in the set
    #[serde(default, rename = "type")]
    pub fw_type: FwType,

    /// Enable IPv6 support
    #[serde(default = "FwOption::default_ipv6")]
    pub ipv6: bool,

    /// Flush IP sets on program initialization
    /// default is true
    #[serde(default = "FwOption::default_flush")]
    pub flush: bool,

    /// Restore IP sets on program initialization
    /// If true, the program will restore the IP sets from the stored map
    /// default is false
    #[serde(default)]
    pub restore: bool,

    /// File to store the IP sets, associated with the `restore` option
    /// If `restore` is true, the program will restore the IP sets from this file
    /// default is None
    #[serde(default)]
    pub file: Option<String>,

    /// Expired time for IPs added to ipset/nftset
    /// After this time, the IP entries in ipset/nftset will be removed
    /// default is 43200 seconds (12 hour)
    #[serde(default = "FwOption::default_timeout")]
    pub timeout: u32,

    /// Netmask for IPv4 addresses (CIDR notation)
    /// default is 32
    #[serde(default = "FwOption::default_netmask_v4")]
    pub netmask_v4: u8,

    /// Netmask for IPv6 addresses (CIDR notation)
    /// default is 64
    #[serde(default = "FwOption::default_netmask_v6")]
    pub netmask_v6: Option<u8>,

    #[serde(default)]
    pub ipset: Option<IpSetOption>,

    #[serde(default)]
    pub nftset: Option<NftSetOption>,
}

impl FwOption {
    #[inline]
    fn default_ipv6() -> bool { true }

    #[inline]
    fn default_flush() -> bool { true }

    #[inline]
    fn default_timeout() -> u32 { 43200 }

    #[inline]
    fn default_netmask_v4() -> u8 { 32 }

    #[inline]
    fn default_netmask_v6() -> Option<u8> { Some(64) }
}

impl Default for FwOption {
    fn default() -> Self {
        FwOption {
            fw_type: FwType::default(),
            ipv6: FwOption::default_ipv6(),
            flush: FwOption::default_flush(),
            restore: false,
            file: None,
            timeout: FwOption::default_timeout(),
            netmask_v4: FwOption::default_netmask_v4(),
            netmask_v6: FwOption::default_netmask_v6(),
            ipset: Some(IpSetOption::default()),
            nftset: None,
        }
    }
}

#[derive(Clone)]
pub struct IpsetSession {
    name: String,
    session: Arc<RwLock<Session<HashNet>>>,
}

impl IpsetSession {
    pub fn new(name: String) -> Self {
        let session = Session::new(name.clone());
        IpsetSession {
            name,
            session: Arc::new(RwLock::new(session)),
        }
    }

    pub fn name(&self) -> &str { &self.name }

    pub fn session(&self) -> Arc<RwLock<Session<HashNet>>> { self.session.clone() }
}

/// IPSet session for IPv4 and IPv6
#[derive(Clone)]
pub struct IpSet {
    /// IPSet session for IPv4
    v4: IpsetSession,

    /// IPSet session for IPv6
    v6: Option<IpsetSession>,

    /// Map of IP addresses and their timestamps added
    /// Used for tracking the expiration of IPs
    ips: Arc<RwLock<HashMap<Cidr, u64>>>,
}

impl IpSet {
    pub fn new(v4: String, v6: Option<String>) -> Self {
        let v4 = IpsetSession::new(v4);
        let v6 = v6.map(IpsetSession::new);
        let ips = Arc::new(RwLock::new(HashMap::new()));

        IpSet { v4, v6, ips }
    }

    pub fn v4(&self) -> &IpsetSession { &self.v4 }

    pub fn v6(&self) -> Option<&IpsetSession> { self.v6.as_ref() }

    pub fn save(&self, _file: &str) -> Result<()> {
        // TODO: Implement save functionality
        unimplemented!()
    }

    /// Restore IPSet from the stored map
    pub fn restore(&self, _file: &str) -> Result<()> {
        // TODO: Implement restore functionality
        unimplemented!()
    }

    pub fn flush(&self) -> Result<()> {
        self.v4().session().write().flush()?;

        if let Some(v6) = self.v6() {
            v6.session.write().flush()?;
        }

        // Clear the IPs map
        self.ips.write().clear();

        Ok(())
    }

    pub fn add(&self, ip: &Cidr) -> Result<String> {
        let set = if ip.is_ipv4() {
            self.v4().session().write().add(ip, &[])?;
            self.v4().name().to_string()
        } else if let Some(v6) = self.v6() {
            v6.session.write().add(ip, &[])?;
            v6.name().to_string()
        } else {
            return Err("IPv6 is not supported".into());
        };

        // Store the timestamp of the added IP
        self.ips.write().insert(ip.clone(), timestamp());

        Ok(set)
    }

    pub fn del(&self, ip: &Cidr) -> Result<String> {
        let set = if ip.is_ipv4() {
            self.v4().session().write().del(ip)?;
            self.v4().name().to_string()
        } else if let Some(v6) = self.v6() {
            v6.session().write().del(ip)?;
            v6.name().to_string()
        } else {
            return Err("IPv6 is not supported".into());
        };

        // Remove the IP from the map
        self.ips.write().remove(ip);

        Ok(set)
    }

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
            if let Err(e) = self.del(ip) {
                warn!("Failed to unblock IP <{ip}>: {e}");
            } else {
                released.push(ip.clone());
            }
        }

        released
    }
}

/// Manually managed firewall, only manages ipset
#[derive(Clone)]
pub struct NoneFw(IpSet);

/// Iptables session for IPv4 and IPv6
pub struct Iptables {
    /// IPTables session for IPv4
    pub v4: IPTables,
    /// IPTables session for IPv6
    pub v6: Option<IPTables>,
}

impl Iptables {
    pub fn init(ipv6: bool) -> Result<Self> {
        Ok(Iptables {
            v4: iptables::new(false)
                .map_err(|e| format!("Failed to initialize IPv4 iptables: {e}"))?,
            v6: if ipv6 {
                Some(
                    iptables::new(true)
                        .map_err(|e| format!("Failed to initialize IPv6 iptables: {e}"))?,
                )
            } else {
                None
            },
        })
    }

    pub fn v4(&self) -> &IPTables { &self.v4 }

    pub fn v6(&self) -> Option<&IPTables> { self.v6.as_ref() }
}

/// Iptables firewall
#[derive(Clone)]
pub struct IptablesFw {
    /// IPTables session, None if manually managed
    ipt: Arc<Iptables>,

    /// IPSet session, can be used unmanaged iptables firewall
    ipset: IpSet,
}

impl IptablesFw {
    pub fn init(ipv6: bool, ipset_v4: String, ipset_v6: Option<String>) -> Result<Self> {
        let firewall = IptablesFw {
            ipt: Arc::new(Iptables::init(ipv6)?),
            ipset: IpSet::new(ipset_v4, ipset_v6),
        };
        firewall.__create_rules()?;

        Ok(firewall)
    }

    /// Create iptables rules for IPv4 or IPv6
    fn __setup_iptables(ipt: &IPTables, ipset_name: &str, is_ipv6: bool) -> Result<()> {
        let version_str = if is_ipv6 { "ip6tables" } else { "iptables" };

        // Check if the chain exists
        match ipt.chain_exists(DEFAULT_IPTABLES_TABLE, DEFAULT_IPTABLES_CHAIN) {
            Ok(exists) => {
                if !exists {
                    ipt.new_chain(DEFAULT_IPTABLES_TABLE, DEFAULT_IPTABLES_CHAIN)
                        .map_err(|e| format!("Failed to create {version_str} chain: {e}"))?;
                }
            }
            Err(e) => {
                return Err(format!("Failed to check {version_str} chain: {e}").into());
            }
        }

        // Append rule to the chain
        ipt.append_replace(
            DEFAULT_IPTABLES_TABLE,
            DEFAULT_IPTABLES_CHAIN,
            &DEFAULT_IPTABLES_RULE.replace("{ipset}", ipset_name),
        )
        .map_err(|e| format!("Failed to create {version_str} rule: {e}"))?;

        // Hook
        ipt.append_replace(
            DEFAULT_IPTABLES_TABLE,
            DEFAULT_IPTABLES_CHAIN_HOOK,
            &format!("-j {DEFAULT_IPTABLES_CHAIN}"),
        )
        .map_err(|e| format!("Failed to create {version_str} rule: {e}"))?;

        Ok(())
    }

    fn __create_rules(&self) -> Result<&Self> {
        // Create iptables rules for IPv4
        Self::__setup_iptables(self.ipt.v4(), &self.ipset.v4.name, false)?;

        // Create iptables rules for IPv6 if enabled
        if let Some(ipt) = self.ipt.v6()
            && let Some(ipset_v6) = &self.ipset.v6
        {
            Self::__setup_iptables(ipt, &ipset_v6.name, true)?;
        }

        Ok(self)
    }
}

#[derive(Clone)]
pub struct NftSet {
    name: String,
}

impl NftSet {
    pub fn new(name: &str) -> Self {
        NftSet {
            name: name.to_string(),
        }
    }

    pub fn name(&self) -> &str { &self.name }

    pub fn save(&self, _file: &str) -> Result<()> {
        // TODO: Implement save functionality
        unimplemented!()
    }

    pub fn restore(&self, _file: &str) -> Result<()> {
        // TODO: Implement restore functionality
        unimplemented!()
    }

    pub fn flush(&self) -> Result<()> {
        let mut batch = Batch::new();
        batch.add_cmd(schema::NfCmd::Flush(schema::FlushObject::Set(Box::new(
            NftablesFW::default_nft_set(&self.name),
        ))));

        helper::apply_ruleset(&batch.to_nftables())?;

        Ok(())
    }

    pub fn add(&self, _ip: &Cidr) -> Result<String> {
        // TODO: Implement add functionality
        unimplemented!()
    }

    pub fn del(&self, _ip: &Cidr) -> Result<String> {
        // TODO: Implement delete functionality
        unimplemented!()
    }
}

/// Nftables firewall
#[derive(Clone)]
pub struct NftablesFW {
    pub nftset: NftSet,
}

impl NftablesFW {
    pub fn init(nftset: &str) -> Result<Self> {
        let firewall = NftablesFW {
            nftset: NftSet::new(nftset),
        };
        firewall.create_ruleset()?;

        Ok(firewall)
    }

    /// Default nftables table for blocking IPs
    ///
    /// Equivalent to:
    /// ```bash
    /// nft add table inet aria2-peer-block-table
    /// ```
    fn default_nft_table<'a>() -> schema::Table<'a> {
        schema::Table {
            family: types::NfFamily::INet,
            name: DEFAULT_NFTABLES_TABLE.into(),
            ..Default::default()
        }
    }

    /// Default nftables chain for blocking IPs
    ///
    /// Equivalent to:
    /// ```bash
    /// nft add chain inet aria2-peer-block-table aria2-peer-block-chain { type filter hook prerouting priority -300; policy accept; }
    /// ```
    fn default_nft_chain<'a>() -> schema::Chain<'a> {
        schema::Chain {
            family: types::NfFamily::INet,
            table: DEFAULT_NFTABLES_TABLE.into(),
            name: DEFAULT_NFTABLES_CHAIN.into(),
            _type: Some(DEFAULT_NFTABLES_CHAIN_TYPE),
            hook: Some(DEFAULT_NFTABLES_CHAIN_HOOK),
            prio: Some(DEFAULT_NFTABLES_CHAIN_PRIORITY),
            policy: Some(DEFAULT_NFTABLES_CHAIN_POLICY),
            ..Default::default()
        }
    }

    /// Default nftables set for blocking IPs
    ///
    /// Equivalent to:
    /// ```bash
    /// nft add set inet aria2-peer-block-table ${name} { type ipv4_addr . ipv6_addr; flags interval; }
    /// ```
    fn default_nft_set<'a>(name: &'a str) -> schema::Set<'a> {
        schema::Set {
            family: types::NfFamily::IP,
            table: DEFAULT_NFTABLES_TABLE.into(),
            name: name.into(),
            set_type: DEFAULT_NFTABLES_SET_TYPE,
            flags: Some([schema::SetFlag::Interval].into_iter().collect()),
            ..Default::default()
        }
    }

    /// Default nftables rules for blocking IPs
    ///
    /// Equivalent to:
    /// ```bash
    /// nft add rule inet aria2-peer-block-table aria2-peer-block-chain ip sddr @${name} drop
    /// nft add rule inet aria2-peer-block-table aria2-peer-block-chain ip6 sddr @${name} drop
    /// ```
    fn default_nft_rules<'a>(set: &'a str) -> Vec<schema::Rule<'a>> {
        vec![
            schema::Rule {
                family: types::NfFamily::IP,
                table: DEFAULT_NFTABLES_TABLE.into(),
                chain: DEFAULT_NFTABLES_CHAIN.into(),
                expr: Cow::Owned(vec![
                    stmt::Statement::Match(stmt::Match {
                        left: expr::Expression::String(Cow::Borrowed("ip sddr")),
                        right: expr::Expression::String(format!("@{set}").into()),
                        op: stmt::Operator::EQ,
                    }),
                    stmt::Statement::Counter(stmt::Counter::Anonymous(None)),
                    stmt::Statement::Drop(None),
                ]),
                ..Default::default()
            },
            schema::Rule {
                family: types::NfFamily::IP6,
                table: DEFAULT_NFTABLES_TABLE.into(),
                chain: DEFAULT_NFTABLES_CHAIN.into(),
                expr: Cow::Owned(vec![
                    stmt::Statement::Match(stmt::Match {
                        left: expr::Expression::String(Cow::Borrowed("ip6 sddr")),
                        right: expr::Expression::String(format!("@{set}").into()),
                        op: stmt::Operator::EQ,
                    }),
                    stmt::Statement::Counter(stmt::Counter::Anonymous(None)),
                    stmt::Statement::Drop(None),
                ]),
                ..Default::default()
            },
        ]
    }

    fn create_ruleset(&self) -> Result<()> {
        let mut batch = Batch::new();

        // Create the table, chain, and set
        batch.add(schema::NfListObject::Table(NftablesFW::default_nft_table()));
        batch.add(schema::NfListObject::Chain(NftablesFW::default_nft_chain()));
        batch.add(schema::NfListObject::Set(Box::new(
            NftablesFW::default_nft_set(self.nftset.name()),
        )));
        NftablesFW::default_nft_rules(self.nftset.name())
            .into_iter()
            .for_each(|rule| batch.add(schema::NfListObject::Rule(rule)));

        helper::apply_ruleset(&batch.to_nftables())?;

        Ok(())
    }
}

#[derive(Clone)]
pub enum FwSession {
    /// Unmanaged firewall
    None(NoneFw),

    /// Managed iptables firewall
    Iptables(IptablesFw),

    /// Managed nftables firewall
    Nftables(NftablesFW),
}

impl FwSession {
    pub fn ipset(&self) -> Option<&IpSet> {
        match self {
            FwSession::None(none) => Some(&none.0),
            FwSession::Iptables(ipt) => Some(&ipt.ipset),
            FwSession::Nftables(_) => None,
        }
    }
}

/// Firewall manager for handling IP blocking
#[derive(Clone)]
pub struct Firewall {
    /// Firewall options
    option: Arc<RwLock<FwOption>>,

    /// Firewall session
    session: FwSession,
}

impl Firewall {
    pub fn init(option: FwOption) -> Result<Self> {
        match option.fw_type {
            FwType::Iptables | FwType::None => {
                assert!(
                    option.ipset.is_some(),
                    "IpSet option is required for ipset set type"
                );
            }
            FwType::Nftables => {
                assert!(
                    option.nftset.is_some(),
                    "NftSet option is required for nftset set type"
                );
            }
        }

        let ipset_v4 = option.ipset.as_ref().unwrap().set_v4.clone();
        let ipset_v6 = option.ipset.as_ref().unwrap().set_v6.as_ref().cloned();
        let flush = option.flush;

        let session = match option.fw_type {
            FwType::None => FwSession::None(NoneFw(IpSet::new(ipset_v4, ipset_v6))),
            FwType::Iptables => {
                let ipt = IptablesFw::init(option.ipv6, ipset_v4, ipset_v6)?;
                FwSession::Iptables(ipt)
            }
            FwType::Nftables => FwSession::Nftables(NftablesFW::init(
                option.nftset.as_ref().unwrap().set.as_str(),
            )?),
        };

        let firewall = Firewall {
            option: Arc::new(RwLock::new(option)),
            session,
        };

        // Flush the IPSet/Nftset if required
        if flush {
            firewall.flush()?;
        } else {
            // Restore the IPSet/Nftset if not flushing
            firewall.restore()?;
        }

        Ok(firewall)
    }

    pub fn session(&self) -> &FwSession { &self.session }

    pub fn netmask_v4(&self) -> u8 { self.option.read().netmask_v4 }

    pub fn netmask_v6(&self) -> Option<u8> { self.option.read().netmask_v6 }

    /// Flush the IPSet/Nftset
    pub fn flush(&self) -> Result<&Self> {
        match self.session {
            FwSession::None(ref none) => {
                none.0.flush()?;
            }
            FwSession::Iptables(ref ipt) => {
                ipt.ipset.flush()?;
            }
            FwSession::Nftables(ref nft) => {
                nft.nftset.flush()?;
            }
        }

        Ok(self)
    }

    /// Restore the IPSet/Nftset from the stored map
    pub fn restore(&self) -> Result<&Self> {
        if let Some(ref file) = self.option.read().file {
            match self.session {
                FwSession::None(ref none) => {
                    none.0.restore(file)?;
                }
                FwSession::Iptables(ref ipt) => {
                    ipt.ipset.restore(file)?;
                }
                FwSession::Nftables(ref nft) => {
                    nft.nftset.restore(file)?;
                }
            }
        }

        Ok(self)
    }

    pub fn block(&self, ip: &Cidr) -> Result<String> {
        let set = match self.session {
            FwSession::None(ref none) => none.0.add(ip)?,
            FwSession::Iptables(ref ipt) => ipt.ipset.add(ip)?,
            FwSession::Nftables(ref nft) => nft.nftset.add(ip)?,
        };

        Ok(set)
    }

    pub fn unblock(&self, ip: &Cidr) -> Result<&Self> {
        match self.session {
            FwSession::None(ref none) => {
                none.0.del(ip)?;
            }
            FwSession::Iptables(ref ipt) => {
                ipt.ipset.del(ip)?;
            }
            FwSession::Nftables(ref nft) => {
                nft.nftset.del(ip)?;
            }
        }

        Ok(self)
    }
}
