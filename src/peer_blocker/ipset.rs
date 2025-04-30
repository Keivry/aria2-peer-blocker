use serde::Deserialize;

/// Configuration options for Linux IPSet integration
#[derive(Clone, Debug, Deserialize)]
pub struct IPSetOption {
    /// Flush IPSet tables on program initialization
    #[serde(default = "IPSetOption::default_flush")]
    pub flush: bool,

    /// IPSet table name for IPv4 addresses
    #[serde(default = "IPSetOption::default_v4")]
    pub v4: String,

    /// Netmask for IPv4 addresses (CIDR notation)
    #[serde(default = "IPSetOption::default_netmask_v4")]
    pub netmask_v4: u8,

    /// IPSet table name for IPv6 addresses
    #[serde(default = "IPSetOption::default_v6")]
    pub v6: String,

    /// Netmask for IPv6 addresses (CIDR notation)
    #[serde(default = "IPSetOption::default_netmask_v6")]
    pub netmask_v6: u8,
}

impl IPSetOption {
    #[inline]
    fn default_flush() -> bool { true }

    #[inline]
    fn default_v4() -> String { "PeerBlock".to_string() }

    #[inline]
    fn default_netmask_v4() -> u8 { 32 }

    #[inline]
    fn default_v6() -> String { "PeerBlockv6".to_string() }

    #[inline]
    fn default_netmask_v6() -> u8 { 64 }
}

impl Default for IPSetOption {
    fn default() -> Self {
        IPSetOption {
            flush: IPSetOption::default_flush(),
            v4: IPSetOption::default_v4(),
            netmask_v4: IPSetOption::default_netmask_v4(),
            v6: IPSetOption::default_v6(),
            netmask_v6: IPSetOption::default_netmask_v6(),
        }
    }
}
