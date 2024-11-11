//! MITM Tools Library
//!
//! This library provides functionality for network scanning and traffic monitoring.
//! It contains utilities for network operations such as CIDR parsing and IP address
//! manipulation.

use std::net::Ipv4Addr;

/// Network-related functionality module
pub mod network {
    use super::*;

    /// Parses a CIDR notation string into an IP address and subnet mask.
    ///
    /// # Arguments
    ///
    /// * `cidr` - A string slice containing the CIDR notation (e.g., "192.168.1.0/24")
    ///
    /// # Returns
    ///
    /// * `Ok((Ipv4Addr, u8))` - Tuple containing the network address and subnet mask
    /// * `Err(String)` - Error message if parsing fails
    ///
    /// # Examples
    ///
    /// ```
    /// use mitm_tools::network::parse_cidr;
    ///
    /// let result = parse_cidr("192.168.1.0/24");
    /// assert!(result.is_ok());
    /// ```
    pub fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format".to_string());
        }

        let ip = parts[0]
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("Invalid IP address: {}", e))?;
        let mask = parts[1]
            .parse::<u8>()
            .map_err(|e| format!("Invalid subnet mask: {}", e))?;

        if mask > 32 {
            return Err("Subnet mask must be between 0 and 32".to_string());
        }

        Ok((ip, mask))
    }

    /// Generates a list of all valid IP addresses in a given network.
    ///
    /// # Arguments
    ///
    /// * `network` - The network address
    /// * `mask` - The subnet mask in CIDR notation
    ///
    /// # Returns
    ///
    /// A vector containing all valid host IP addresses in the network,
    /// excluding the network address and broadcast address.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use mitm_tools::network::get_network_ips;
    ///
    /// let network = Ipv4Addr::new(192, 168, 1, 0);
    /// let ips = get_network_ips(network, 24);
    /// assert_eq!(ips.len(), 254); // 256 - 2 (network + broadcast)
    /// ```
    pub fn get_network_ips(network: Ipv4Addr, mask: u8) -> Vec<Ipv4Addr> {
        let ip_u32 = u32::from(network);
        let network_size = 2u32.pow(32 - mask as u32);
        let network_start = ip_u32 & (u32::MAX << (32 - mask));

        (network_start + 1..network_start + network_size - 1)
            .map(|ip| Ipv4Addr::from(ip))
            .collect()
    }
}
