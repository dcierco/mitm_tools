//! # MITM Tools Library
//!
//! A library for network monitoring and man-in-the-middle analysis, providing tools
//! for network scanning, traffic monitoring, and packet analysis.
//!
//! ## Features
//!
//! * Network scanning and host discovery
//! * Traffic monitoring and analysis
//! * Protocol-specific packet parsing (DNS, HTTP, HTTPS)
//! * Raw socket handling and packet dissection
//!
//! ## Security Notice
//!
//! This library is intended for educational and authorized testing purposes only.
//! Usage of this library for attacking targets without prior mutual consent is illegal.
//!
//! ## Architecture
//!
//! The library is organized into several modules:
//! * `network`: Core networking utilities and CIDR operations
//! * `packet_analyzer`: Raw packet analysis and protocol parsing

use std::net::Ipv4Addr;

/// Network-related functionality for IP address manipulation and network calculations
pub mod network {
    use super::*;

    /// Parses a CIDR notation string into an IP address and subnet mask
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
    ///
    /// let (ip, mask) = result.unwrap();
    /// assert_eq!(ip.to_string(), "192.168.1.0");
    /// assert_eq!(mask, 24);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The CIDR format is invalid (missing '/' separator)
    /// * The IP address portion cannot be parsed
    /// * The subnet mask is not between 0 and 32
    pub fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format: missing subnet mask".to_string());
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

    /// Generates a list of all valid IP addresses in a given network range
    ///
    /// # Arguments
    ///
    /// * `network` - The network address (e.g., 192.168.1.0)
    /// * `mask` - The subnet mask in CIDR notation (e.g., 24 for /24)
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
    ///
    /// // A /24 network has 254 usable host addresses (256 - network - broadcast)
    /// assert_eq!(ips.len(), 254);
    ///
    /// // First usable IP is x.x.x.1
    /// assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
    ///
    /// // Last usable IP is x.x.x.254
    /// assert_eq!(ips[253], Ipv4Addr::new(192, 168, 1, 254));
    /// ```
    ///
    /// # Implementation Details
    ///
    /// The function calculates the network range by:
    /// 1. Converting the network address to a 32-bit integer
    /// 2. Calculating the network size based on the subnet mask
    /// 3. Generating IP addresses within the valid host range
    /// 4. Excluding network address (first) and broadcast address (last)
    pub fn get_network_ips(network: Ipv4Addr, mask: u8) -> Vec<Ipv4Addr> {
        let ip_u32 = u32::from(network);
        let network_size = 2u32.pow(32 - mask as u32);
        let network_start = ip_u32 & (u32::MAX << (32 - mask));

        // Generate range excluding network address and broadcast address
        (network_start + 1..network_start + network_size - 1)
            .map(|ip| Ipv4Addr::from(ip))
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_parse_cidr_valid() {
            let result = parse_cidr("192.168.1.0/24").unwrap();
            assert_eq!(result.0.to_string(), "192.168.1.0");
            assert_eq!(result.1, 24);
        }

        #[test]
        fn test_parse_cidr_invalid_format() {
            assert!(parse_cidr("192.168.1.0").is_err());
        }

        #[test]
        fn test_parse_cidr_invalid_mask() {
            assert!(parse_cidr("192.168.1.0/33").is_err());
        }

        #[test]
        fn test_get_network_ips() {
            let ips = get_network_ips(Ipv4Addr::new(192, 168, 1, 0), 24);
            assert_eq!(ips.len(), 254);
            assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(ips[253], Ipv4Addr::new(192, 168, 1, 254));
        }
    }
}

/// Packet analysis functionality for network traffic monitoring
pub mod packet_analyzer;
