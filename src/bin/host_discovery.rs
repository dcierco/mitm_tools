//! Host Discovery Binary
//!
//! This binary provides functionality for scanning a network to discover active hosts
//! using ICMP echo requests (ping).

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

/// Command line arguments structure
#[derive(Parser)]
#[command(name = "host_discovery")]
#[command(author = "Daniel Cierco")]
#[command(version = "1.0")]
#[command(about = "Network host discovery tool", long_about = None)]
struct Args {
    /// Network CIDR (e.g., 192.168.1.0/24)
    #[arg(short, long)]
    network: String,

    /// Timeout in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    timeout: u64,
}

/// Represents information about a discovered host
#[derive(Debug)]
struct HostInfo {
    /// IP address of the host
    ip: Ipv4Addr,
    /// Response time for ICMP echo request
    response_time: Duration,
}

/// Creates an ICMP echo request packet
///
/// # Arguments
///
/// * `buffer` - Mutable buffer to store the packet
///
/// # Returns
///
/// A mutable ICMP echo request packet
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
/// * `network` - CIDR notation of the network to scan
/// * `timeout_ms` - Timeout in milliseconds for each host
///
/// # Returns
///
/// Result indicating success or containing error message
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

    debug!("Scanning {} hosts", total_hosts);
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
fn main() {
    env_logger::init();
    let args = Args::parse();

    info!("Starting host discovery for network: {}", args.network);

    if let Err(e) = scan_network(&args.network, args.timeout) {
        error!("Scan failed: {}", e);
        std::process::exit(1);
    }
}
