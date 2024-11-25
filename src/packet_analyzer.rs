// src/packet_analyzer.rs

use chrono::{DateTime, Utc};
use log::{debug, info, trace, warn};
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug)]
pub enum PacketType {
    DNS(String), // Domain name
    HTTP(HttpRequest),
    HTTPS(String), // Domain name
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub title: Option<String>,
    pub protocol: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
}

#[derive(Default)]
struct TcpStream {
    data: Vec<u8>,
}

pub struct PacketAnalyzer {
    target_ip: IpAddr,
    tcp_streams: HashMap<(IpAddr, u16, IpAddr, u16), TcpStream>,
}

impl PacketAnalyzer {
    pub fn new(target_ip: IpAddr) -> Self {
        info!("Initializing packet analyzer for target IP: {}", target_ip);
        Self {
            target_ip,
            tcp_streams: HashMap::new(),
        }
    }

    pub fn get_target_ip(&self) -> IpAddr {
        self.target_ip
    }

    pub fn analyze_packet(&mut self, packet_data: &[u8]) -> PacketType {
        if packet_data.len() < 34 {
            // Minimum size for IPv4 + TCP/UDP header
            return PacketType::Unknown;
        }

        // Extract IP header (assuming Ethernet + IPv4)
        let ip_header_start = 14; // Skip Ethernet header
        let ip_header = &packet_data[ip_header_start..];

        // Verify IP version
        if (ip_header[0] >> 4) != 4 {
            // Check if IPv4
            return PacketType::Unknown;
        }

        let ip_header_len = (ip_header[0] & 0x0f) * 4;
        let protocol = ip_header[9];

        let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
        let dst_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);

        // Get transport layer header
        let transport_header_start = ip_header_start + ip_header_len as usize;
        if packet_data.len() < transport_header_start + 4 {
            return PacketType::Unknown;
        }

        let transport_header = &packet_data[transport_header_start..];
        let src_port = ((transport_header[0] as u16) << 8) | transport_header[1] as u16;
        let dst_port = ((transport_header[2] as u16) << 8) | transport_header[3] as u16;

        // Log packet details for debugging
        debug!(
            "Packet: {}:{} -> {}:{} (protocol: {})",
            src_ip, src_port, dst_ip, dst_port, protocol
        );

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

    fn analyze_dns(&self, data: &[u8]) -> PacketType {
        if data.len() < 42 {
            // Minimum DNS packet size
            return PacketType::Unknown;
        }

        let dns_start = 42; // Skip Ethernet + IP + UDP headers
        let dns_data = &data[dns_start..];

        debug!("DNS packet length: {}", dns_data.len());

        // Print first few bytes of DNS data for debugging
        if dns_data.len() >= 12 {
            debug!("DNS Header: {:?}", &dns_data[..12]);
        }

        // Check if it's a query (QR bit in DNS header)
        if dns_data.len() < 12 || (dns_data[2] & 0x80) != 0 {
            trace!("Ignoring DNS response packet");
            return PacketType::Unknown;
        }

        let mut pos = 12; // Skip DNS header
        let mut domain = String::new();

        while pos < dns_data.len() {
            let len = dns_data[pos] as usize;
            if len == 0 {
                break;
            }

            if pos + 1 + len > dns_data.len() {
                warn!("Malformed DNS packet: length exceeds packet size");
                return PacketType::Unknown;
            }

            if !domain.is_empty() {
                domain.push('.');
            }

            if let Ok(label) = std::str::from_utf8(&dns_data[pos + 1..pos + 1 + len]) {
                domain.push_str(label);
            } else {
                warn!("Invalid UTF-8 in DNS label");
                return PacketType::Unknown;
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

    fn analyze_http(&mut self, data: &[u8]) -> PacketType {
        if data.len() < 54 {
            // Minimum size for Ethernet + IP + TCP headers
            return PacketType::Unknown;
        }

        let ip_header_start = 14;
        let ip_header = &data[ip_header_start..];
        let ip_header_len = ((ip_header[0] & 0x0f) * 4) as usize;

        let tcp_header_start = ip_header_start + ip_header_len;
        let tcp_header = &data[tcp_header_start..];
        let tcp_header_len = ((tcp_header[12] >> 4) * 4) as usize;

        // Get payload offset
        let payload_start = tcp_header_start + tcp_header_len;
        if payload_start >= data.len() {
            return PacketType::Unknown;
        }

        // Extract payload
        let payload = &data[payload_start..];
        if payload.is_empty() {
            return PacketType::Unknown;
        }

        // TCP flags
        let tcp_flags = tcp_header[13];
        let is_psh = (tcp_flags & 0x08) != 0;

        // Source and destination information
        let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
        let dst_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);
        let src_port = ((tcp_header[0] as u16) << 8) | tcp_header[1] as u16;
        let dst_port = ((tcp_header[2] as u16) << 8) | tcp_header[3] as u16;

        // Debug print payload
        if let Ok(payload_str) = std::str::from_utf8(payload) {
            debug!("TCP Payload: {}", payload_str);
        }

        let stream_key = (IpAddr::V4(src_ip), src_port, IpAddr::V4(dst_ip), dst_port);

        let stream = self.tcp_streams.entry(stream_key).or_default();
        stream.data.extend_from_slice(payload);

        if is_psh {
            if let Ok(str_data) = std::str::from_utf8(&stream.data) {
                debug!("Processing HTTP data: {}", str_data);

                // Look for HTTP request
                if str_data.contains("HTTP/1.1") || str_data.contains("HTTP/1.0") {
                    let lines: Vec<&str> = str_data.lines().collect();
                    if let Some(first_line) = lines.first() {
                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let method = parts[0].to_string();
                            let path = parts[1].to_string();

                            let host = lines
                                .iter()
                                .find(|line| line.starts_with("Host: "))
                                .map(|line| line.trim_start_matches("Host: ").trim())
                                .unwrap_or("");

                            let url = if host.is_empty() {
                                path.clone()
                            } else {
                                format!("http://{}{}", host, path)
                            };

                            let title = extract_title(str_data);

                            info!("Captured HTTP request: {} {}", method, url);

                            stream.data.clear();

                            return PacketType::HTTP(HttpRequest {
                                method,
                                url,
                                title,
                                protocol: "HTTP/1".to_string(),
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }
            }
            stream.data.clear();
        }

        PacketType::Unknown
    }

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

        // Debug payload
        debug!(
            "TLS payload length: {}, first bytes: {:?}",
            payload.len(),
            &payload[..std::cmp::min(payload.len(), 10)]
        );

        // Check for ClientHello (record type 0x16, version 0x0301 or 0x0302 or 0x0303)
        if payload.len() >= 5 &&
           payload[0] == 0x16 && // Handshake
           payload[1] == 0x03 && // TLS version major
           (payload[2] <= 0x03) && // TLS version minor
           payload.len() >= (((payload[3] as usize) << 8) | payload[4] as usize) + 5
        // Check full record length
        {
            debug!("Found TLS handshake message");

            // Handshake message type is at offset 5
            if payload.len() > 5 && payload[5] == 0x01 {
                // ClientHello
                debug!("Found ClientHello message");

                if let Some(sni) = extract_sni(payload) {
                    info!("Detected HTTPS connection to: {}", sni);
                    return PacketType::HTTPS(sni);
                }
            }
        }

        PacketType::Unknown
    }
}

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

fn extract_sni(tls_data: &[u8]) -> Option<String> {
    debug!(
        "Attempting to extract SNI from payload of length {}",
        tls_data.len()
    );

    if tls_data.len() < 43 {
        trace!("TLS data too short for SNI");
        return None;
    }

    // Get handshake message length
    let handshake_length = ((tls_data[3] as usize) << 8) | tls_data[4] as usize;
    debug!("Handshake length: {}", handshake_length);

    if tls_data.len() < 5 + handshake_length {
        trace!("Incomplete TLS handshake message");
        return None;
    }

    // Parse ClientHello to find extensions
    let mut pos = 43; // Skip fixed ClientHello fields

    // Skip session ID if present
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

    // Now we're at the extensions
    if pos + 2 <= tls_data.len() {
        let extensions_length = ((tls_data[pos] as usize) << 8) | tls_data[pos + 1] as usize;
        debug!("Extensions length: {}", extensions_length);
        pos += 2;

        let extensions_end = pos + extensions_length;
        while pos + 4 <= extensions_end {
            let extension_type = ((tls_data[pos] as u16) << 8) | tls_data[pos + 1] as u16;
            let extension_length = ((tls_data[pos + 2] as u16) << 8) | tls_data[pos + 3] as u16;
            debug!(
                "Extension type: {}, length: {}",
                extension_type, extension_length
            );

            // SNI extension type is 0
            if extension_type == 0 && pos + 4 + extension_length as usize <= tls_data.len() {
                // Parse SNI
                if extension_length >= 5 {
                    let sni_length =
                        ((tls_data[pos + 7] as usize) << 8) | tls_data[pos + 8] as usize;
                    if pos + 9 + sni_length <= tls_data.len() {
                        if let Ok(sni) =
                            std::str::from_utf8(&tls_data[pos + 9..pos + 9 + sni_length])
                        {
                            debug!("Found SNI: {}", sni);
                            return Some(sni.to_string());
                        }
                    }
                }
            }
            pos += 4 + extension_length as usize;
        }
    }

    None
}
