//! # Host Discovery Binary
//!
//! A network scanning tool that discovers active hosts on a network using ICMP echo requests (ping).
//!
//! ## Operation
//!
//! The tool performs network scanning by:
//! 1. Parsing the target network range in CIDR notation
//! 2. Creating ICMP echo request packets
//! 3. Sending packets to each potential host
//! 4. Recording responses and timing information
//!
//! ## Network Packet Structure
//!
//! ```text
//! ICMP Echo Request/Reply:
//! +------------------+------------------+------------------+
//! |     Type (8)    |    Code (0)     |     Checksum    |
//! +------------------+------------------+------------------+
//! |    Identifier   |  Sequence Number |                 |
//! +------------------+------------------+     Payload     |
//! |                    Optional Data                     |
//! +---------------------------------------------------->
//! ```

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use log::{debug, error, info, warn};
use pnet::packet::icmp::echo_request::{IcmpCodes, MutableEchoRequestPacket};
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
};
use pnet::util;

use mitm_tools::network::{get_network_ips, parse_cidr};

/// Command line arguments for the host discovery tool
///
/// # Example
///
/// ```text
/// host_discovery -n 192.168.1.0/24 -t 1000
/// ```
#[derive(Parser)]
#[command(name = "host_discovery")]
#[command(author, version)]
#[command(about = "Network host discovery tool")]
#[command(
    long_about = "A network scanning tool that discovers active hosts using ICMP echo requests.\n\
    \n\
    USAGE:\n\
      host_discovery -n <NETWORK_CIDR> [-t <TIMEOUT>]\n\
    \n\
    EXAMPLES:\n\
      # Scan local network with default timeout\n\
      host_discovery -n 192.168.1.0/24\n\
      \n\
      # Scan with custom timeout (in milliseconds)\n\
      host_discovery -n 192.168.1.0/24 -t 2000\n\
    \n\
    FEATURES:\n\
      - ICMP echo request (ping) based scanning\n\
      - Parallel host discovery\n\
      - Response time measurement\n\
      - Configurable timeout per host\n\
    \n\
    The tool will output:\n\
      - Total hosts in network\n\
      - Number of active hosts found\n\
      - Individual host response times\n\
      - Total scan duration"
)]
struct Args {
    /// Network CIDR (e.g., 192.168.1.0/24)
    #[arg(short, long)]
    network: String,

    /// Timeout in milliseconds for each host scan
    #[arg(short, long, default_value_t = 1000)]
    timeout: u64,
}

/// Information about a discovered active host on the network
///
/// This structure contains both the IP address of the discovered host
/// and the round-trip time of the ICMP echo request/reply.
#[derive(Debug)]
struct HostInfo {
    /// IPv4 address of the discovered host
    ip: Ipv4Addr,
    /// Time taken for the host to respond to the ICMP echo request
    response_time: Duration,
}

/// Creates an ICMP echo request packet (ping)
///
/// # Arguments
///
/// * `buffer` - Pre-allocated buffer to store the packet
///
/// # Returns
///
/// A mutable ICMP echo request packet ready to be sent
///
/// # Packet Structure
///
/// The created packet follows the ICMP protocol structure:
/// - Type: Echo Request (8)
/// - Code: No Code (0)
/// - Identifier: 42 (arbitrary)
/// - Sequence: 1
/// - Checksum: Calculated based on packet content
///
/// # Examples
///
/// ```no_run
/// let mut buffer = vec![0u8; 64];
/// let packet = create_icmp_packet(&mut buffer);
/// // packet can now be sent using a transport channel
/// ```
fn create_icmp_packet(buffer: &mut [u8]) -> MutableEchoRequestPacket {
    let mut packet = MutableEchoRequestPacket::new(buffer).unwrap();
    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(IcmpCodes::NoCode);
    packet.set_identifier(42);
    packet.set_sequence_number(1);
    let checksum = util::checksum(packet.packet(), 1);
    packet.set_checksum(checksum);
    packet
}

/// Performs network scan to discover active hosts
///
/// # Arguments
///
/// * `network` - Network range in CIDR notation (e.g., "192.168.1.0/24")
/// * `timeout_ms` - Maximum time to wait for each host's response
///
/// # Returns
///
/// * `Ok(())` - Scan completed successfully
/// * `Err(String)` - Error occurred during scanning
///
/// # Implementation Details
///
/// The function:
/// 1. Creates a transport channel for ICMP communication
/// 2. Generates list of IP addresses to scan
/// 3. Sends ICMP echo requests to each address
/// 4. Records responses and timing information
/// 5. Prints summary of discovered hosts
///
/// # Example Output
///
/// ```text
/// Scan Results:
/// Total hosts in network: 254
/// Active hosts found: 12
/// Total scan time: 5.234s
///
/// Active Hosts:
/// IP: 192.168.1.1, Response Time: 2ms
/// IP: 192.168.1.5, Response Time: 1ms
/// ...
/// ```
///
/// # Notes
///
/// * Requires root/administrator privileges due to raw socket usage
/// * May be blocked by firewalls or security policies
fn scan_network(network: &str, timeout_ms: u64) -> Result<(), String> {
    let (network_addr, mask) = parse_cidr(network)?;
    let timeout = Duration::from_millis(timeout_ms);

    // Create transport channel for ICMP packets
    let (mut tx, mut rx) = transport_channel(
        1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .map_err(|e| format!("Failed to create channel: {}", e))?;

    let active_hosts = Arc::new(Mutex::new(Vec::new()));
    let ips = get_network_ips(network_addr, mask);
    let total_hosts = ips.len();

    debug!("Starting scan of {} hosts", total_hosts);
    let scan_start = Instant::now();

    // Scan each IP address in the network
    for ip in ips {
        let mut buffer = vec![0u8; 64];
        let packet = create_icmp_packet(&mut buffer);
        let send_time = Instant::now();

        if let Err(e) = tx.send_to(packet, IpAddr::V4(ip)) {
            warn!("Failed to send packet to {}: {}", ip, e);
            continue;
        }

        let mut iter = icmp_packet_iter(&mut rx);

        // Wait for response with timeout
        match iter.next_with_timeout(timeout) {
            Ok(Some((_, addr))) => {
                if addr == IpAddr::V4(ip) {
                    let response_time = send_time.elapsed();
                    info!("Host {} is up (latency: {:?})", ip, response_time);

                    let mut hosts = active_hosts.lock().unwrap();
                    hosts.push(HostInfo { ip, response_time });
                }
            }
            Ok(None) => {
                debug!("No response from {}", ip);
            }
            Err(e) => {
                warn!("Error receiving response from {}: {}", ip, e);
            }
        }
    }

    // Print results
    let scan_duration = scan_start.elapsed();
    let active_hosts = active_hosts.lock().unwrap();

    println!("\nScan Results:");
    println!("Total hosts in network: {}", total_hosts);
    println!("Active hosts found: {}", active_hosts.len());
    println!("Total scan time: {:?}", scan_duration);
    println!("\nActive Hosts:");

    for host in active_hosts.iter() {
        println!("IP: {}, Response Time: {:?}", host.ip, host.response_time);
    }

    Ok(())
}

/// Main entry point for the host discovery tool
///
/// Initializes logging, parses command line arguments,
/// and executes the network scan operation.
fn main() {
    env_logger::init();
    let args = Args::parse();

    info!("Starting host discovery for network: {}", args.network);

    if let Err(e) = scan_network(&args.network, args.timeout) {
        error!("Scan failed: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_icmp_packet() {
        let mut buffer = vec![0u8; 64];
        let packet = create_icmp_packet(&mut buffer);

        assert_eq!(packet.get_icmp_type(), IcmpTypes::EchoRequest);
        assert_eq!(packet.get_icmp_code(), IcmpCodes::NoCode);
        assert_eq!(packet.get_identifier(), 42);
        assert_eq!(packet.get_sequence_number(), 1);
    }
}
