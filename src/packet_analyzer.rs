//! # Network Packet Analyzer
//!
//! This module provides low-level packet analysis functionality for network traffic monitoring.
//! It handles raw packet parsing and protocol analysis for DNS, HTTP, and HTTPS traffic.
//!
//! ## Packet Structure Overview
//!
//! ```text
//! Ethernet Frame (14 bytes)
//! +------------------+------------------+------------------+
//! |  Dest MAC (6B)  |  Src MAC (6B)   | EtherType (2B)  |
//! +------------------+------------------+------------------+
//!
//! IPv4 Header (20+ bytes)
//! +------------------+------------------+------------------+
//! | Ver + IHL (1B)  |  ToS (1B)       | Total Len (2B)  |
//! +------------------+------------------+------------------+
//! | Identification (2B)    | Flags + Fragment (2B)       |
//! +------------------+------------------+------------------+
//! |  TTL (1B)       | Protocol (1B)    | Checksum (2B)   |
//! +------------------+------------------+------------------+
//! |               Source IP Address (4B)                  |
//! +-----------------------------------------------------|
//! |             Destination IP Address (4B)              |
//! +-----------------------------------------------------+
//!
//! TCP Header (20+ bytes)
//! +------------------+------------------+------------------+
//! | Src Port (2B)   | Dst Port (2B)   | Seq Num (4B)    |
//! +------------------+------------------+------------------+
//! | Ack Num (4B)    | Data Off + Flags | Window (2B)     |
//! +------------------+------------------+------------------+
//! | Checksum (2B)   | Urgent Ptr (2B)  | Options (0+B)   |
//! +------------------+------------------+------------------+
//! ```

use chrono::{DateTime, Utc};
use log::{debug, info, trace, warn};
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// Represents different types of network packets that can be analyzed
///
/// This enum categorizes packets based on their protocol and content,
/// allowing for protocol-specific handling and analysis.
#[derive(Debug)]
pub enum PacketType {
    /// DNS query packet containing the resolved domain name
    DNS(String),
    /// HTTP request with detailed information about the request
    HTTP(HttpRequest),
    /// HTTPS connection with Server Name Indication (SNI)
    HTTPS(String),
    /// Packets that don't match known protocols or are incomplete
    Unknown,
}

/// Structure representing an HTTP or HTTPS request
///
/// Contains parsed information from HTTP/HTTPS requests including
/// method, URL, and metadata about the request.
///
/// # Example
///
/// ```text
/// HttpRequest {
///     method: "GET",
///     url: "http://example.com/path",
///     title: Some("Example Domain"),
///     protocol: "HTTP/1.1",
///     timestamp: 2024-01-01T00:00:00Z
/// }
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct HttpRequest {
    /// HTTP method (GET, POST, CONNECT, etc.)
    pub method: String,
    /// Complete URL of the request
    pub url: String,
    /// HTML page title if found in response
    pub title: Option<String>,
    /// Protocol version (HTTP/1.1, HTTP/2, HTTPS)
    pub protocol: String,
    /// When the request was captured
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
}

/// Represents a TCP stream for reassembling fragmented packets
///
/// Used to handle TCP segmentation by maintaining a buffer of
/// received data until a complete protocol message is received.
#[derive(Default)]
struct TcpStream {
    /// Accumulated TCP segment data
    data: Vec<u8>,
}

/// Main packet analyzer that maintains state and processes network packets
///
/// Handles packet capture state and provides methods for analyzing
/// different types of network traffic.
pub struct PacketAnalyzer {
    /// IP address of the host being monitored
    target_ip: IpAddr,
    /// Active TCP streams indexed by connection tuple
    /// Key: (source_ip, source_port, dest_ip, dest_port)
    tcp_streams: HashMap<(IpAddr, u16, IpAddr, u16), TcpStream>,
}

impl PacketAnalyzer {
    /// Creates a new packet analyzer instance for a specific target IP
    ///
    /// # Arguments
    ///
    /// * `target_ip` - IP address of the host to monitor
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::IpAddr;
    /// use mitm_tools::packet_analyzer::PacketAnalyzer;
    ///
    /// let target = "192.168.1.100".parse::<IpAddr>().unwrap();
    /// let analyzer = PacketAnalyzer::new(target);
    /// ```
    pub fn new(target_ip: IpAddr) -> Self {
        info!("Initializing packet analyzer for target IP: {}", target_ip);
        Self {
            target_ip,
            tcp_streams: HashMap::new(),
        }
    }

    /// Returns the target IP address being monitored
    pub fn get_target_ip(&self) -> IpAddr {
        self.target_ip
    }

    /// Analyzes a raw network packet and identifies its type and content
    ///
    /// # Packet Structure Analysis
    ///
    /// ```text
    /// Byte Offsets:
    /// [0..13]  : Ethernet Header
    /// [14]     : IP Version & Header Length (first 4 bits each)
    /// [23]     : Protocol (6=TCP, 17=UDP)
    /// [26..29] : Source IP
    /// [30..33] : Destination IP
    /// [34..35] : Source Port
    /// [36..37] : Destination Port
    /// ```
    ///
    /// # Arguments
    ///
    /// * `packet_data` - Raw packet bytes including Ethernet frame
    ///
    /// # Returns
    ///
    /// The analyzed packet type and its contents
    ///
    /// # Protocol Support
    ///
    /// * TCP (protocol 6)
    ///   - Port 80: HTTP
    ///   - Port 443: HTTPS/TLS
    /// * UDP (protocol 17)
    ///   - Port 53: DNS
    pub fn analyze_packet(&mut self, packet_data: &[u8]) -> PacketType {
        if packet_data.len() < 34 {
            // Minimum size for IPv4 + TCP/UDP header
            return PacketType::Unknown;
        }

        // Extract and verify IP header
        let ip_header_start = 14; // Skip Ethernet header
        let ip_header = &packet_data[ip_header_start..];

        // Verify IPv4 (version in high 4 bits should be 4)
        if (ip_header[0] >> 4) != 4 {
            return PacketType::Unknown;
        }

        // Parse IP header fields
        let ip_header_len = (ip_header[0] & 0x0f) * 4; // Length in 32-bit words
        let protocol = ip_header[9];

        // Extract IP addresses
        let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
        let dst_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);

        // Parse transport layer header
        let transport_header_start = ip_header_start + ip_header_len as usize;
        if packet_data.len() < transport_header_start + 4 {
            return PacketType::Unknown;
        }

        let transport_header = &packet_data[transport_header_start..];
        let src_port = ((transport_header[0] as u16) << 8) | transport_header[1] as u16;
        let dst_port = ((transport_header[2] as u16) << 8) | transport_header[3] as u16;

        debug!(
            "Packet: {}:{} -> {}:{} (protocol: {})",
            src_ip, src_port, dst_ip, dst_port, protocol
        );

        // Route packet to appropriate protocol analyzer
        match protocol {
            6 => {
                // TCP
                match (src_port, dst_port) {
                    (80, _) | (_, 80) => self.analyze_http(packet_data),
                    (443, _) | (_, 443) => self.analyze_https(packet_data),
                    _ => PacketType::Unknown,
                }
            }
            17 => {
                // UDP
                if src_port == 53 || dst_port == 53 {
                    self.analyze_dns(packet_data)
                } else {
                    PacketType::Unknown
                }
            }
            _ => PacketType::Unknown,
        }
    }

    /// Analyzes a DNS packet to extract query information
    ///
    /// # DNS Packet Structure
    ///
    /// ```text
    /// DNS Header Format (12 bytes):
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    ID                           |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                  QDCOUNT                        |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                  ANCOUNT                        |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                  NSCOUNT                        |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                  ARCOUNT                        |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// Question Format:
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    QNAME                        |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    QTYPE                        |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    QCLASS                       |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// # Byte Offsets
    ///
    /// * 42: Start of DNS header (after Ethernet + IP + UDP headers)
    /// * 44: Flags (including QR bit)
    /// * 54: Start of question section
    ///
    /// # Important Fields
    ///
    /// * QR bit (bit 0 of byte 44): 0 for query, 1 for response
    /// * QNAME: Domain name in label format (length-prefixed segments)
    ///
    /// # Examples
    ///
    /// DNS query for "example.com":
    /// ```text
    /// QNAME: 7example3com0
    /// Bytes: [0x07]example[0x03]com[0x00]
    /// ```
    fn analyze_dns(&self, data: &[u8]) -> PacketType {
        if data.len() < 42 {
            // Ethernet(14) + IP(20) + UDP(8)
            return PacketType::Unknown;
        }

        let dns_start = 42;
        let dns_data = &data[dns_start..];

        debug!("DNS packet length: {}", dns_data.len());

        // Log DNS header for debugging
        if dns_data.len() >= 12 {
            debug!("DNS Header: {:?}", &dns_data[..12]);
        }

        // Check if it's a query (QR bit in flags)
        if dns_data.len() < 12 || (dns_data[2] & 0x80) != 0 {
            trace!("Ignoring DNS response packet");
            return PacketType::Unknown;
        }

        // Parse domain name from question section
        let mut pos = 12; // Skip DNS header
        let mut domain = String::new();

        // Domain name parsing loop
        while pos < dns_data.len() {
            let len = dns_data[pos] as usize;
            if len == 0 {
                // Root label (end of domain)
                break;
            }

            // Validate label length
            if pos + 1 + len > dns_data.len() {
                warn!("Malformed DNS packet: label length exceeds packet size");
                return PacketType::Unknown;
            }

            // Add dot between labels
            if !domain.is_empty() {
                domain.push('.');
            }

            // Extract and validate label
            match std::str::from_utf8(&dns_data[pos + 1..pos + 1 + len]) {
                Ok(label) => domain.push_str(label),
                Err(_) => {
                    warn!("Invalid UTF-8 in DNS label");
                    return PacketType::Unknown;
                }
            }

            pos += len + 1;
        }

        if !domain.is_empty() {
            info!("DNS Query: {}", domain);
            PacketType::DNS(domain)
        } else {
            PacketType::Unknown
        }
    }

    /// Analyzes HTTP packets and reconstructs HTTP/1.x and HTTP/2 requests
    ///
    /// # Protocol Support
    ///
    /// * HTTP/1.0 and HTTP/1.1 standard requests
    /// * HTTP/2 cleartext (h2c)
    /// * HTTP/1.1 to HTTP/2 upgrades
    ///
    /// # HTTP/1.x Request Format
    /// ```text
    /// METHOD PATH HTTP/1.1\r\n
    /// Host: example.com\r\n
    /// [Other-Headers]\r\n
    /// \r\n
    /// [Optional Body]
    /// ```
    ///
    /// # HTTP/2 Cleartext Format
    /// ```text
    /// PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
    /// [HTTP/2 Binary Frame Format]
    /// ```
    ///
    /// # HTTP/2 Upgrade Format
    /// ```text
    /// GET / HTTP/1.1\r\n
    /// Host: example.com\r\n
    /// Upgrade: h2c\r\n
    /// HTTP2-Settings: [Base64 Settings]\r\n
    /// \r\n
    /// ```
    ///
    /// # TCP Segment Headers
    /// ```text
    /// Offset  Size    Description
    /// 14      20      IP Header
    /// 34      20+     TCP Header (variable length)
    /// 54+     var     HTTP Payload
    /// ```
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes including Ethernet frame
    ///
    /// # Returns
    ///
    /// `PacketType::HTTP` with request details or `PacketType::Unknown`
    ///
    /// # Examples
    ///
    /// HTTP/1.1 Request:
    /// ```text
    /// GET /index.html HTTP/1.1
    /// Host: example.com
    /// ```
    ///
    /// HTTP/2 Cleartext:
    /// ```text
    /// PRI * HTTP/2.0
    ///
    /// SM
    ///
    /// ```
    fn analyze_http(&mut self, data: &[u8]) -> PacketType {
        // Validate minimum packet size (Ethernet + IP + TCP headers)
        if data.len() < 54 {
            trace!("Packet too small for HTTP analysis");
            return PacketType::Unknown;
        }

        // Parse IP header
        let ip_header_start = 14;
        let ip_header = &data[ip_header_start..];
        let ip_header_len = ((ip_header[0] & 0x0f) * 4) as usize;

        // Parse TCP header
        let tcp_header_start = ip_header_start + ip_header_len;
        let tcp_header = &data[tcp_header_start..];
        let tcp_header_len = ((tcp_header[12] >> 4) * 4) as usize;

        // Extract HTTP payload
        let payload_start = tcp_header_start + tcp_header_len;
        if payload_start >= data.len() {
            trace!("No HTTP payload");
            return PacketType::Unknown;
        }

        let payload = &data[payload_start..];
        if payload.is_empty() {
            trace!("Empty HTTP payload");
            return PacketType::Unknown;
        }

        // Extract TCP flags and connection info
        let tcp_flags = tcp_header[13];
        let is_psh = (tcp_flags & 0x08) != 0; // PSH flag indicates complete message

        let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
        let dst_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);
        let src_port = ((tcp_header[0] as u16) << 8) | tcp_header[1] as u16;
        let dst_port = ((tcp_header[2] as u16) << 8) | tcp_header[3] as u16;

        // Log payload for debugging
        if let Ok(payload_str) = std::str::from_utf8(payload) {
            debug!("TCP Payload: {}", payload_str);
        }

        // Track TCP stream for message reassembly
        let stream_key = (IpAddr::V4(src_ip), src_port, IpAddr::V4(dst_ip), dst_port);

        let stream = self.tcp_streams.entry(stream_key).or_default();
        stream.data.extend_from_slice(payload);

        // Process only complete messages (PSH flag set)
        if is_psh {
            if let Ok(str_data) = std::str::from_utf8(&stream.data) {
                debug!("Processing HTTP data: {}", str_data);

                // Check for HTTP/2 cleartext preface
                if str_data.starts_with("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
                    info!("Detected HTTP/2 cleartext connection");
                    stream.data.clear();
                    return PacketType::HTTP(HttpRequest {
                        method: "PRI".to_string(),
                        url: format!("http://{}:{}", dst_ip, dst_port),
                        title: None,
                        protocol: "HTTP/2".to_string(),
                        timestamp: Utc::now(),
                    });
                }

                // Parse HTTP/1.x request
                if str_data.contains("HTTP/1.1") || str_data.contains("HTTP/1.0") {
                    let lines: Vec<&str> = str_data.lines().collect();

                    if let Some(first_line) = lines.first() {
                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let method = parts[0].to_string();
                            let path = parts[1].to_string();

                            // Extract Host header
                            let host = lines
                                .iter()
                                .find(|line| line.starts_with("Host: "))
                                .map(|line| line.trim_start_matches("Host: ").trim())
                                .unwrap_or("");

                            // Check for HTTP/2 upgrade
                            let is_h2_upgrade = lines.iter().any(|line| {
                                line.starts_with("Upgrade: h2c") || line.contains("HTTP2-Settings")
                            });

                            // Construct full URL
                            let url = if host.is_empty() {
                                path.clone()
                            } else {
                                format!("http://{}{}", host, path)
                            };

                            // Extract page title if present
                            let title = extract_title(str_data);

                            let protocol = if is_h2_upgrade { "HTTP/2" } else { "HTTP/1" };

                            info!("Captured {} request: {} {}", protocol, method, url);

                            stream.data.clear();
                            return PacketType::HTTP(HttpRequest {
                                method,
                                url,
                                title,
                                protocol: protocol.to_string(),
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }
            }
            // Clear stream data if we couldn't process it
            stream.data.clear();
        }

        PacketType::Unknown
    }
    /// Analyzes HTTPS/TLS packets for connection information and protocol details
    ///
    /// # TLS Record Format
    /// ```text
    /// +-------------+-------------+-------------+
    /// | Type (1B)  | Ver (2B)    | Length (2B) |
    /// +-------------+-------------+-------------+
    /// |          Payload Data                  |
    /// +---------------------------------------+
    ///
    /// ClientHello Structure:
    /// +-------------+-------------+-------------+
    /// | Type (1B)  | Length (3B) | Ver (2B)   |
    /// +-------------+-------------+-------------+
    /// | Random (32B)                          |
    /// +---------------------------------------+
    /// | Session ID Length (1B)                |
    /// +---------------------------------------+
    /// | Session ID (0-32B)                    |
    /// +---------------------------------------+
    /// | Cipher Suites Length (2B)             |
    /// +---------------------------------------+
    /// | Cipher Suites                         |
    /// +---------------------------------------+
    /// | Compression Methods Length (1B)        |
    /// +---------------------------------------+
    /// | Compression Methods                    |
    /// +---------------------------------------+
    /// | Extensions Length (2B)                 |
    /// +---------------------------------------+
    /// | Extensions                            |
    /// +---------------------------------------+
    /// ```
    ///
    /// # Important TLS Extensions
    ///
    /// * SNI (type 0): Server Name Indication
    /// * ALPN (type 16): Application Layer Protocol Negotiation
    ///   - Identifies HTTP/2 ("h2") support
    ///
    /// # Returns
    ///
    /// `PacketType::HTTPS` with server name and protocol version
    fn analyze_https(&self, data: &[u8]) -> PacketType {
        if data.len() < 54 {
            trace!("Packet too small for HTTPS analysis");
            return PacketType::Unknown;
        }

        let ip_header_start = 14;
        let ip_header = &data[ip_header_start..];
        let ip_header_len = ((ip_header[0] & 0x0f) * 4) as usize;

        let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);

        // Only process packets from our target
        if IpAddr::V4(src_ip) != self.target_ip {
            trace!("Not from target IP");
            return PacketType::Unknown;
        }

        let tcp_header_start = ip_header_start + ip_header_len;
        if data.len() < tcp_header_start + 20 {
            trace!("Packet too small for TCP header");
            return PacketType::Unknown;
        }

        let tcp_header = &data[tcp_header_start..];
        let tcp_header_len = ((tcp_header[12] >> 4) * 4) as usize;
        let payload_start = tcp_header_start + tcp_header_len;

        if data.len() < payload_start + 5 {
            trace!("No TLS payload");
            return PacketType::Unknown;
        }

        let payload = &data[payload_start..];

        // Extract TLS record information
        if let Some((sni, protocol)) = extract_tls_info(payload) {
            info!("Detected {} connection to: {}", protocol, sni);
            return PacketType::HTTPS(sni); // Return just the SNI string
        }

        PacketType::Unknown
    }
}

/// Extracts HTML page title from HTTP response data
///
/// Searches for <title> tags in HTTP response bodies and extracts
/// the content between them. Handles basic HTML entities and
/// whitespace normalization.
///
/// # Arguments
///
/// * `data` - HTTP response data as string
///
/// # Returns
///
/// Optional string containing the page title if found
fn extract_title(data: &str) -> Option<String> {
    if let Some(start) = data.to_lowercase().find("<title>") {
        if let Some(end) = data[start..].to_lowercase().find("</title>") {
            let title = data[start + 7..start + end].trim().to_string();
            debug!("Found page title: {}", title);
            return Some(title);
        }
    }
    None
}

/// Extracts TLS extensions information from ClientHello message
///
/// # Arguments
///
/// * `tls_data` - TLS record payload starting at record header
///
/// # Returns
///
/// Optional tuple containing (server_name, protocol_version)
///
/// # TLS Extension Format
/// ```text
/// Extension:
/// +-------------+-------------+
/// | Type (2B)  | Length (2B) |
/// +-------------+-------------+
/// | Data (Length bytes)      |
/// +-------------------------+
///
/// SNI Extension (Type 0):
/// +-------------+-------------+
/// | List Len(2B)| Name Type  |
/// +-------------+-------------+
/// | Name Len(2B)| Host Name  |
/// +-------------+-------------+
///
/// ALPN Extension (Type 16):
/// +-------------+-------------+
/// | List Len(2B)| Proto Len  |
/// +-------------+-------------+
/// | Protocol Name            |
/// +-------------------------+
/// ```
fn extract_tls_info(tls_data: &[u8]) -> Option<(String, String)> {
    let mut sni = None;
    let mut is_h2 = false;

    if tls_data.len() < 43 {
        trace!("TLS data too short for extensions");
        return None;
    }

    // Verify ClientHello
    if !(tls_data[0] == 0x16 && // Handshake
             tls_data[1] == 0x03 && // TLS version major
             tls_data[5] == 0x01)
    // ClientHello
    {
        return None;
    }

    let mut pos = 43; // Skip fixed ClientHello fields

    // Skip session ID
    if pos < tls_data.len() {
        let session_id_length = tls_data[pos] as usize;
        pos += 1 + session_id_length;
    }

    // Skip cipher suites
    if pos + 2 <= tls_data.len() {
        let cipher_suites_length = ((tls_data[pos] as usize) << 8) | tls_data[pos + 1] as usize;
        pos += 2 + cipher_suites_length;
    }

    // Skip compression methods
    if pos + 1 <= tls_data.len() {
        let compression_methods_length = tls_data[pos] as usize;
        pos += 1 + compression_methods_length;
    }

    // Parse extensions
    if pos + 2 <= tls_data.len() {
        let extensions_length = ((tls_data[pos] as usize) << 8) | tls_data[pos + 1] as usize;
        debug!("Extensions length: {}", extensions_length);
        pos += 2;

        let extensions_end = pos + extensions_length;
        while pos + 4 <= extensions_end {
            let extension_type = ((tls_data[pos] as u16) << 8) | tls_data[pos + 1] as u16;
            let extension_length = ((tls_data[pos + 2] as u16) << 8) | tls_data[pos + 3] as u16;

            match extension_type {
                0 => {
                    // SNI
                    if extension_length >= 5 {
                        let sni_length =
                            ((tls_data[pos + 7] as usize) << 8) | tls_data[pos + 8] as usize;
                        if pos + 9 + sni_length <= tls_data.len() {
                            if let Ok(server_name) =
                                std::str::from_utf8(&tls_data[pos + 9..pos + 9 + sni_length])
                            {
                                sni = Some(server_name.to_string());
                            }
                        }
                    }
                }
                16 => {
                    // ALPN
                    is_h2 = check_alpn_h2(&tls_data[pos..pos + 4 + extension_length as usize]);
                }
                _ => {}
            }

            pos += 4 + extension_length as usize;
        }
    }

    sni.map(|s| {
        (
            s,
            if is_h2 {
                "HTTP/2".to_string()
            } else {
                "HTTPS".to_string()
            },
        )
    })
}

/// Checks if ALPN extension includes HTTP/2 protocol
///
/// # Arguments
///
/// * `extension_data` - ALPN extension data including header
///
/// # Returns
///
/// true if HTTP/2 ("h2") is in the protocol list
fn check_alpn_h2(extension_data: &[u8]) -> bool {
    if extension_data.len() < 8 {
        return false;
    }

    let alpn_list_length = ((extension_data[4] as usize) << 8) | extension_data[5] as usize;
    let mut pos = 6;

    while pos < 6 + alpn_list_length {
        let proto_len = extension_data[pos] as usize;
        pos += 1;

        if proto_len == 2
            && pos + 2 <= extension_data.len()
            && &extension_data[pos..pos + 2] == b"h2"
        {
            return true;
        }

        pos += proto_len;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Helper function to create a basic IPv4 packet
    fn create_test_packet(protocol: u8, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 54]; // Minimum size for Ethernet + IP + TCP

        // Ethernet header (14 bytes)
        packet[12] = 0x08; // EtherType IPv4
        packet[13] = 0x00;

        // IP header
        packet[14] = 0x45; // Version 4, IHL 5
        packet[23] = protocol; // Protocol (TCP=6, UDP=17)

        // Source IP (192.168.1.100)
        packet[26] = 192;
        packet[27] = 168;
        packet[28] = 1;
        packet[29] = 100;

        // Destination IP (192.168.1.1)
        packet[30] = 192;
        packet[31] = 168;
        packet[32] = 1;
        packet[33] = 1;

        // Transport header (TCP/UDP)
        packet[34] = (src_port >> 8) as u8;
        packet[35] = src_port as u8;
        packet[36] = (dst_port >> 8) as u8;
        packet[37] = dst_port as u8;

        if protocol == 6 {
            // TCP specific
            packet[46] = 0x50; // Data offset
            packet[47] = 0x18; // PSH + ACK flags
        }

        // Add payload
        packet.extend_from_slice(payload);

        packet
    }

    #[test]
    fn test_new_packet_analyzer() {
        let ip = IpAddr::from_str("192.168.1.100").unwrap();
        let analyzer = PacketAnalyzer::new(ip);
        assert_eq!(analyzer.get_target_ip(), ip);
        assert!(analyzer.tcp_streams.is_empty());
    }

    #[test]
    fn test_analyze_dns_query() {
        let target_ip = IpAddr::from_str("192.168.1.100").unwrap();
        let mut analyzer = PacketAnalyzer::new(target_ip);

        // Create DNS query packet for "example.com"
        let dns_payload = vec![
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // Questions
            0x00, 0x00, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Query for example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // Root label
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        // Create full packet with correct offsets
        let mut packet = vec![0; 42]; // Ethernet(14) + IP(20) + UDP(8)
        let src_port = 5312_u16;

        // IP header
        packet[14] = 0x45; // IPv4, IHL=5
        packet[23] = 17; // Protocol = UDP

        // Source IP (target IP)
        packet[26] = 192;
        packet[27] = 168;
        packet[28] = 1;
        packet[29] = 100;

        // UDP ports
        packet[34] = (src_port >> 8) as u8;
        // High byte
        packet[35] = (src_port & 0xFF) as u8;
        // Low byte
        packet[36] = 0;
        // Port 53 (DNS)
        packet[37] = 53;

        // Add DNS payload
        packet.extend_from_slice(&dns_payload);

        match analyzer.analyze_packet(&packet) {
            PacketType::DNS(domain) => {
                assert_eq!(domain, "example.com");
            }
            other => panic!("Expected DNS packet type, got {:?}", other),
        }
    }

    #[test]
    fn test_analyze_http_request() {
        let target_ip = IpAddr::from_str("192.168.1.100").unwrap();
        let mut analyzer = PacketAnalyzer::new(target_ip);

        let http_payload = b"GET /index.html HTTP/1.1\r\n\
            Host: example.com\r\n\
            User-Agent: test\r\n\
            \r\n";

        let packet = create_test_packet(6, 12345, 80, http_payload);

        if let PacketType::HTTP(request) = analyzer.analyze_packet(&packet) {
            assert_eq!(request.method, "GET");
            assert_eq!(request.url, "http://example.com/index.html");
            assert_eq!(request.protocol, "HTTP/1");
        } else {
            panic!("Expected HTTP packet type");
        }
    }

    #[test]
    fn test_analyze_http2_cleartext() {
        let target_ip = IpAddr::from_str("192.168.1.100").unwrap();
        let mut analyzer = PacketAnalyzer::new(target_ip);

        let http2_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let packet = create_test_packet(6, 12345, 80, http2_payload);

        if let PacketType::HTTP(request) = analyzer.analyze_packet(&packet) {
            assert_eq!(request.method, "PRI");
            assert_eq!(request.protocol, "HTTP/2");
        } else {
            panic!("Expected HTTP packet type");
        }
    }

    #[test]
    fn test_analyze_https_request() {
        let target_ip = IpAddr::from_str("192.168.1.100").unwrap();
        let mut analyzer = PacketAnalyzer::new(target_ip);

        // Create packet with TLS ClientHello
        let mut packet = vec![0; 54]; // Ethernet + IP + TCP headers

        // IP header
        packet[14] = 0x45; // IPv4, IHL=5
        packet[23] = 6; // Protocol = TCP

        // Source IP (target IP - must match analyzer's target)
        packet[26] = 192;
        packet[27] = 168;
        packet[28] = 1;
        packet[29] = 100;

        // TCP header
        let src_port = 1234_u16;
        packet[34] = (src_port >> 8) as u8;
        packet[35] = (src_port & 0xFF) as u8;
        packet[36] = (443_u16 >> 8) as u8;
        packet[37] = (443_u16 & 0xFF) as u8;
        packet[46] = 0x50; // Data offset
        packet[47] = 0x18; // PSH + ACK flags

        // TLS ClientHello with SNI
        // Calculate lengths first
        let hostname = b"example.com";
        let hostname_len = hostname.len();
        let sni_extension_len = hostname_len + 5; // hostname + SNI entry header
        let extension_list_len = sni_extension_len + 4; // SNI extension + extension header
        let handshake_len = 42 + extension_list_len; // fixed fields + extensions
        let record_len = handshake_len + 4; // handshake + handshake header

        let mut tls_payload = vec![
            0x16, // Handshake
            0x03,
            0x01,                             // TLS version
            ((record_len >> 8) & 0xFF) as u8, // Length high byte
            (record_len & 0xFF) as u8,        // Length low byte
            0x01,                             // ClientHello
            0x00,                             // Handshake length (3 bytes)
            ((handshake_len >> 8) & 0xFF) as u8,
            (handshake_len & 0xFF) as u8,
            0x03,
            0x03, // TLS 1.2
            // 32 bytes random
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            0x18,
            0x19,
            0x1a,
            0x1b,
            0x1c,
            0x1d,
            0x1e,
            0x1f,
            0x00, // Session ID length
            0x00,
            0x02, // Cipher suites length
            0x00,
            0x1d,                                     // Cipher suite
            0x01,                                     // Compression methods length
            0x00,                                     // Compression method null
            ((extension_list_len >> 8) & 0xFF) as u8, // Extensions length high byte
            (extension_list_len & 0xFF) as u8,        // Extensions length low byte
            0x00,
            0x00,                                    // Extension type (server_name)
            ((sni_extension_len >> 8) & 0xFF) as u8, // SNI extension length high byte
            (sni_extension_len & 0xFF) as u8,        // SNI extension length low byte
            0x00,                                    // Server name list length high byte
            (hostname_len + 3) as u8,                // Server name list length low byte
            0x00,                                    // Name type (hostname)
            ((hostname_len >> 8) & 0xFF) as u8,      // Hostname length high byte
            (hostname_len & 0xFF) as u8,             // Hostname length low byte
        ];

        // Add hostname
        tls_payload.extend_from_slice(hostname);

        // Add the TLS payload to the packet
        packet.extend_from_slice(&tls_payload);

        // Debug print
        println!("Packet length: {}", packet.len());
        println!("TLS payload length: {}", tls_payload.len());
        println!("Record length: {}", record_len);
        println!("Handshake length: {}", handshake_len);
        println!("Extension list length: {}", extension_list_len);
        println!("SNI extension length: {}", sni_extension_len);
        println!("Hostname length: {}", hostname_len);

        match analyzer.analyze_packet(&packet) {
            PacketType::HTTPS(domain) => {
                assert_eq!(domain, "example.com");
            }
            other => panic!("Expected HTTPS packet type, got {:?}", other),
        }
    }

    #[test]
    fn test_extract_title() {
        let html = "<html><head><title>Test Page</title></head><body>Content</body></html>";
        assert_eq!(extract_title(html), Some("Test Page".to_string()));

        let html_no_title = "<html><body>No title</body></html>";
        assert_eq!(extract_title(html_no_title), None);
    }

    #[test]
    fn test_invalid_packet_sizes() {
        let target_ip = IpAddr::from_str("192.168.1.100").unwrap();
        let mut analyzer = PacketAnalyzer::new(target_ip);

        // Test packets that are too small
        let small_packet = vec![0; 33]; // Minimum is 34
        assert!(matches!(
            analyzer.analyze_packet(&small_packet),
            PacketType::Unknown
        ));

        // Test invalid IP version
        let mut invalid_ip = vec![0; 54];
        invalid_ip[14] = 0x60; // IPv6
        assert!(matches!(
            analyzer.analyze_packet(&invalid_ip),
            PacketType::Unknown
        ));
    }

    #[test]
    fn test_tcp_stream_reassembly() {
        let target_ip = IpAddr::from_str("192.168.1.100").unwrap();
        let mut analyzer = PacketAnalyzer::new(target_ip);

        // First packet without PSH flag
        let mut packet1 = vec![0; 54];
        packet1[14] = 0x45; // IPv4, IHL=5
        packet1[23] = 6; // Protocol = TCP

        // Source IP (must be target IP)
        packet1[26] = 192;
        packet1[27] = 168;
        packet1[28] = 1;
        packet1[29] = 100;

        // TCP header
        let src_port = 1234_u16;
        packet1[34] = (src_port >> 8) as u8;
        packet1[35] = (src_port & 0xFF) as u8;
        packet1[36] = 0; // Destination port (80)
        packet1[37] = 80;
        packet1[46] = 0x50; // Data offset
        packet1[47] = 0x10; // ACK flag only

        // First part of HTTP request
        let payload1 = b"GET /index.html HTTP/1.1\r\nHo";
        packet1.extend_from_slice(payload1);

        // First packet should return Unknown (no PSH flag)
        let result1 = analyzer.analyze_packet(&packet1);
        assert!(matches!(result1, PacketType::Unknown));

        // Second packet with PSH flag and rest of the request
        let mut packet2 = vec![0; 54];
        // Copy IP and TCP headers
        packet2[..54].copy_from_slice(&packet1[..54]);
        // Set PSH flag
        packet2[47] = 0x18; // PSH + ACK flags

        // Add the rest of the HTTP request
        let payload2 = b"st: example.com\r\n\r\n";
        packet2.extend_from_slice(payload2);

        // Second packet should complete the HTTP request
        match analyzer.analyze_packet(&packet2) {
            PacketType::HTTP(request) => {
                assert_eq!(request.method, "GET");
                assert_eq!(request.url, "http://example.com/index.html");
            }
            other => panic!("Expected HTTP packet type, got {:?}", other),
        }
    }
}
