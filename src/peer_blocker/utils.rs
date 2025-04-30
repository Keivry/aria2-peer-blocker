use std::{
    fmt::{Display, Formatter, Result},
    net::IpAddr,
};

use chrono::Local;
use ipset::types::NetDataType;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Cidr {
    ip: IpAddr,
    netmask: u8,
}

impl Cidr {
    pub fn new(ip: IpAddr, netmask: u8) -> Self { cidr(ip, netmask) }
}

impl Display for Cidr {
    fn fmt(&self, f: &mut Formatter) -> Result { write!(f, "{}/{}", self.ip, self.netmask) }
}

impl From<&Cidr> for NetDataType {
    fn from(cidr: &Cidr) -> NetDataType { NetDataType::new(cidr.ip, cidr.netmask) }
}

pub fn timestamp() -> u64 { Local::now().timestamp() as u64 }

/// Convert IP and netmask to CIDR format.
/// ip: 192.168.1.1 and netmask: 24 -> 192.168.1.0/24
/// ip: 2001:db8::1 and netmask: 64 -> 2001:db8::/64
fn cidr(ip: IpAddr, netmask: u8) -> Cidr {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let mask = !((1 << (32 - netmask)) - 1);
            let network = u32::from_be_bytes(octets) & mask;
            Cidr {
                ip: IpAddr::V4(network.to_be_bytes().into()),
                netmask,
            }
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let mut network = [0u16; 8];
            let mut bits = netmask;
            for (i, segment) in segments.iter().enumerate() {
                if bits >= 16 {
                    network[i] = *segment;
                    bits -= 16;
                } else if bits > 0 {
                    network[i] = segment & (!0 << (16 - bits));
                    bits = 0;
                } else {
                    network[i] = 0;
                }
            }
            Cidr {
                ip: IpAddr::V6(network.into()),
                netmask,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::cidr;

    #[test]
    fn test_cidr() {
        assert_eq!(
            cidr("192.168.0.1".parse().unwrap(), 24).to_string(),
            "192.168.0.0/24"
        );
        assert_eq!(
            cidr("2001:db8::aaa:1".parse().unwrap(), 64).to_string(),
            "2001:db8::/64"
        );
    }
}
