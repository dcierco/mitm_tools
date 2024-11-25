// src/packet_analyzer.rs

use log::{debug, info, trace, warn};
use serde::Serialize;
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
}

pub struct PacketAnalyzer {
    target_ip: IpAddr,
}

impl PacketAnalyzer {
    pub fn new(target_ip: IpAddr) -> Self {
        info!("Initializing packet analyzer for target IP: {}", target_ip);
        Self { target_ip }
    }

    pub fn analyze_packet(&self, packet_data: &[u8]) -> PacketType {
        // Early return if packet is too small
        if packet_data.len() < 40 {
            trace!("Packet too small: {} bytes", packet_data.len());
            return PacketType::Unknown;
        }

        // Extract IP addresses from IP header
        let src_ip = Ipv4Addr::new(
            packet_data[12],
            packet_data[13],
            packet_data[14],
            packet_data[15],
        );
        let dst_ip = Ipv4Addr::new(
            packet_data[16],
            packet_data[17],
            packet_data[18],
            packet_data[19],
        );

        // Filter for target IP
        let is_target_source = IpAddr::V4(src_ip) == self.target_ip;
        let is_target_dest = IpAddr::V4(dst_ip) == self.target_ip;

        if !is_target_source && !is_target_dest {
            trace!(
                "Ignoring packet not related to target IP. Src: {}, Dst: {}",
                src_ip,
                dst_ip
            );
            return PacketType::Unknown;
        }

        let protocol = packet_data[9];
        let src_port = ((packet_data[20] as u16) << 8) | packet_data[21] as u16;
        let dst_port = ((packet_data[22] as u16) << 8) | packet_data[23] as u16;

        debug!(
            "Analyzing target packet - Protocol: {}, Src: {}:{}, Dst: {}:{}",
            protocol, src_ip, src_port, dst_ip, dst_port
        );

        match (protocol, src_port, dst_port) {
            // DNS packet (UDP, port 53)
            (17, 53, _) | (17, _, 53) => {
                debug!("DNS packet detected from target");
                if is_target_source {
                    info!("Target is making DNS query");
                } else {
                    info!("DNS response to target");
                }
                self.analyze_dns(packet_data)
            }

            // HTTPS packet (TCP, port 443)
            (6, 443, _) | (6, _, 443) => {
                debug!("HTTPS packet detected from target");
                if is_target_source {
                    info!("Target is making HTTPS request");
                } else {
                    info!("HTTPS response to target");
                }
                self.analyze_https(packet_data)
            }

            // HTTP packet (TCP, port 80)
            (6, 80, _) | (6, _, 80) => {
                debug!("HTTP packet detected from target");
                if is_target_source {
                    info!("Target is making HTTP request");
                } else {
                    info!("HTTP response to target");
                }
                self.analyze_http(packet_data)
            }

            _ => {
                trace!("Unknown protocol {} for target traffic", protocol);
                PacketType::Unknown
            }
        }
    }

    fn analyze_dns(&self, data: &[u8]) -> PacketType {
        // Skip IP (20 bytes) and UDP (8 bytes) headers
        if data.len() < 28 {
            return PacketType::Unknown;
        }

        let dns_data = &data[28..];

        // Basic DNS header parsing (12 bytes)
        if dns_data.len() < 12 {
            return PacketType::Unknown;
        }

        // Check if it's a query (QR bit in DNS header)
        let is_query = (dns_data[2] & 0x80) == 0;
        if !is_query {
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

            // Prevent buffer overflow
            if pos + 1 + len > dns_data.len() {
                warn!("Malformed DNS packet: length exceeds packet size");
                return PacketType::Unknown;
            }

            // Add dot between labels
            if !domain.is_empty() {
                domain.push('.');
            }

            // Extract label
            if let Ok(label) = std::str::from_utf8(&dns_data[pos + 1..pos + 1 + len]) {
                domain.push_str(label);
            } else {
                warn!("Invalid UTF-8 in DNS label");
                return PacketType::Unknown;
            }

            pos += len + 1;
        }

        if domain.is_empty() {
            PacketType::Unknown
        } else {
            info!("Target DNS query for domain: {}", domain);
            PacketType::DNS(domain)
        }
    }

    fn analyze_http(&self, data: &[u8]) -> PacketType {
        // Skip IP (20 bytes) and TCP (20 bytes) headers
        let payload = &data[40..];

        if let Ok(str_data) = std::str::from_utf8(payload) {
            let first_line = str_data.lines().next().unwrap_or("");

            // Detect HTTP method
            let methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT"];
            for method in methods.iter() {
                if first_line.starts_with(method) {
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        // Extract host from headers
                        let host = str_data
                            .lines()
                            .find(|line| line.starts_with("Host: "))
                            .and_then(|line| Some(line.trim_start_matches("Host: ").trim()))
                            .unwrap_or("");

                        let url = if host.is_empty() {
                            parts[1].to_string()
                        } else {
                            format!("http://{}{}", host, parts[1])
                        };

                        // Extract title if present
                        let title = extract_title(str_data);

                        let protocol = if first_line.contains("HTTP/2") {
                            "HTTP/2"
                        } else {
                            "HTTP/1"
                        };

                        info!("Target HTTP request: {} {} ({})", method, url, protocol);
                        return PacketType::HTTP(HttpRequest {
                            method: method.to_string(),
                            url,
                            title,
                            protocol: protocol.to_string(),
                        });
                    }
                }
            }
        }

        PacketType::Unknown
    }

    fn analyze_https(&self, data: &[u8]) -> PacketType {
        // For HTTPS, we can only detect the connection establishment
        if data.len() > 40 {
            let payload = &data[40..];

            // Try to extract SNI (Server Name Indication) from ClientHello
            if let Some(domain) = extract_sni(payload) {
                info!("Target HTTPS connection to: {}", domain);
                return PacketType::HTTPS(domain);
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
    if tls_data.len() < 5 {
        return None;
    }

    // Check if it's a ClientHello message
    if tls_data[0] != 0x16 || // Handshake
       tls_data[1] != 0x03 || // TLS version major
       tls_data[5] != 0x01
    // ClientHello
    {
        return None;
    }

    // Skip to extensions
    let mut pos = 43; // Fixed offset to extensions length
    while pos + 4 < tls_data.len() {
        let extension_type = ((tls_data[pos] as u16) << 8) | tls_data[pos + 1] as u16;
        let extension_length = ((tls_data[pos + 2] as u16) << 8) | tls_data[pos + 3] as u16;

        // SNI extension type is 0
        if extension_type == 0 && pos + 4 + extension_length as usize <= tls_data.len() {
            // Parse SNI
            if let Ok(sni) =
                std::str::from_utf8(&tls_data[pos + 9..pos + 4 + extension_length as usize])
            {
                debug!("Found SNI in ClientHello: {}", sni);
                return Some(sni.to_string());
            }
        }

        pos += 4 + extension_length as usize;
    }

    None
}
