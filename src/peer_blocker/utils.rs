use std::{
    fmt::{Display, Formatter, Result},
    net::IpAddr,
    ops::Deref,
};

use chrono::Local;
use ipset::types::NetDataType;

/// Represents an IP address in CIDR notation (IP/netmask)
/// Used for IP range matching and network operations
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Cidr {
    /// Network address portion
    ip: IpAddr,
    /// Network mask prefix length
    netmask: u8,
}

impl Cidr {
    /// Creates a new CIDR with the given IP address and network mask
    /// Automatically converts the IP to the network address based on the mask
    pub fn new(ip: IpAddr, netmask: u8) -> Self { cidr(ip, netmask) }
}

impl Deref for Cidr {
    type Target = IpAddr;

    /// Deref to get the IP address portion of the CIDR
    fn deref(&self) -> &Self::Target { &self.ip }
}

/// Implements string representation for CIDR in standard notation (e.g., "192.168.0.0/24")
impl Display for Cidr {
    fn fmt(&self, f: &mut Formatter) -> Result { write!(f, "{}/{}", self.ip, self.netmask) }
}

/// Conversion from Cidr to ipset's NetDataType for use with the ipset library
impl From<&Cidr> for NetDataType {
    fn from(cidr: &Cidr) -> NetDataType { NetDataType::new(cidr.ip, cidr.netmask) }
}

/// Returns the current timestamp as seconds since Unix epoch
pub fn timestamp() -> u64 { Local::now().timestamp() as u64 }

/// Converts an IP address and netmask to proper CIDR format by zeroing host bits
///
/// # Examples
///
/// - IP: 192.168.1.1 with netmask 24 becomes 192.168.1.0/24
/// - IP: 2001:db8::1 with netmask 64 becomes 2001:db8::/64
///
/// # Parameters
///
/// - `ip`: Any IPv4 or IPv6 address
/// - `netmask`: Prefix length (1-32 for IPv4, 1-128 for IPv6)
///
/// # Returns
///
/// A Cidr struct with the network portion of the address and specified netmask
fn cidr(ip: IpAddr, netmask: u8) -> Cidr {
    match ip {
        // For IPv4 addresses
        IpAddr::V4(ipv4) => {
            // Convert IP to byte array
            let octets = ipv4.octets();
            // Create a bitmask with 1s in network portion, 0s in host portion
            let mask = !((1 << (32 - netmask)) - 1);
            // Apply mask to get network address
            let network = u32::from_be_bytes(octets) & mask;
            Cidr {
                ip: IpAddr::V4(network.to_be_bytes().into()),
                netmask,
            }
        }
        // For IPv6 addresses
        IpAddr::V6(ipv6) => {
            // Get 16-bit segments of the IPv6 address
            let segments = ipv6.segments();
            // Create new array for network address
            let mut network = [0u16; 8];
            // Track remaining bits to process
            let mut bits = netmask;

            // Process each 16-bit segment
            for (i, segment) in segments.iter().enumerate() {
                if bits >= 16 {
                    // If we have 16+ bits remaining, keep entire segment
                    network[i] = *segment;
                    bits -= 16;
                } else if bits > 0 {
                    // If we have <16 bits, apply partial mask
                    network[i] = segment & (!0 << (16 - bits));
                    bits = 0;
                } else {
                    // No bits remaining, zero out segment
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

    /// Tests the CIDR conversion function with both IPv4 and IPv6 addresses
    #[test]
    fn test_cidr() {
        // Test IPv4 CIDR conversion
        assert_eq!(
            cidr("192.168.0.1".parse().unwrap(), 24).to_string(),
            "192.168.0.0/24"
        );

        // Test IPv6 CIDR conversion
        assert_eq!(
            cidr("2001:db8::aaa:1".parse().unwrap(), 64).to_string(),
            "2001:db8::/64"
        );
    }
}
