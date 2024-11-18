//! Traffic Monitor Binary
//!
//! This binary provides functionality for monitoring network traffic,
//! specifically focusing on HTTP and DNS traffic for a target host.
//! It generates a live-updating HTML report of browsing history.

use chrono::serde::ts_seconds;
use chrono::{DateTime, Local, Utc};
use clap::Parser;
use core::str;
use handlebars::Handlebars;
use log::{debug, error, info};
use pcap::{Capture, Device};
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Command line arguments structure
#[derive(Parser)]
#[command(name = "traffic_monitor")]
#[command(author = "Daniel Cierco")]
#[command(version = "1.0")]
#[command(about = "Network traffic monitoring tool", long_about = None)]
struct Args {
    /// Target IP address to monitor
    #[arg(short, long)]
    target: String,

    /// Network interface to monitor
    #[arg(short, long)]
    interface: Option<String>,

    /// Output directory for HTML report
    #[arg(short, long, default_value = "report")]
    output: String,
}

/// Represents a captured DNS query with timestamp
#[derive(Debug, Clone, Serialize)]
struct DnsQuery {
    /// Domain name being queried
    domain: String,
    /// Timestamp of when the query was captured
    #[serde(serialize_with = "ts_seconds::serialize")]
    timestamp: DateTime<Utc>,
}

/// Represents a captured HTTP request with metadata
#[derive(Debug, Clone, Serialize)]
struct HttpRequest {
    /// Requested URL
    url: String,
    /// HTTP method (GET, POST, etc.)
    method: String,
    /// Timestamp of when the request was captured
    #[serde(serialize_with = "ts_seconds::serialize")]
    timestamp: DateTime<Utc>,
    /// Page title if available
    title: Option<String>,
    /// Protocol used (HTTP, HTTP/2 or HTTPS)
    protocol: String,
}

/// Structure for passing data to the HTML template
#[derive(Serialize)]
struct TemplateData {
    /// Monitoring start time
    start_time: String,
    /// Duration of monitoring
    duration: String,
    /// Total number of packets processed
    packet_count: usize,
    /// Number of DNS queries captured
    dns_count: usize,
    /// Number of HTTP requests captured
    http_count: usize,
    /// List of captured HTTP requests
    http_requests: Vec<HttpRequest>,
    /// List of captured DNS queries
    dns_queries: Vec<DnsQuery>,
}

/// Structure to store traffic statistics and captured data
#[derive(Debug, Clone)]
struct TrafficStats {
    /// List of captured DNS queries
    dns_queries: Vec<DnsQuery>,
    /// List of captured HTTP requests
    http_requests: Vec<HttpRequest>,
    /// Total number of packets processed
    packet_count: usize,
    /// Time when monitoring started
    start_time: DateTime<Utc>,
}

impl TrafficStats {
    /// Creates a new TrafficStats instance
    fn new() -> Self {
        TrafficStats {
            dns_queries: Vec::new(),
            http_requests: Vec::new(),
            packet_count: 0,
            start_time: Utc::now(),
        }
    }

    /// Adds a new DNS query to the statistics
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain name that was queried
    fn add_dns_query(&mut self, domain: String) {
        self.dns_queries.push(DnsQuery {
            domain,
            timestamp: Utc::now(),
        });
    }

    /// Adds a new HTTP request to the statistics
    ///
    /// # Arguments
    ///
    /// * `url` - The requested URL
    /// * `method` - The HTTP method used
    /// * `title` - Optional page title
    fn add_http_request(&mut self, url: String, method: String, title: Option<String>) {
        self.http_requests.push(HttpRequest {
            url,
            method,
            timestamp: Utc::now(),
            title,
            protocol: "HTTP".to_string(),
        });
    }

    fn add_https_request(&mut self, domain: &str) {
        self.http_requests.push(HttpRequest {
            url: format!("https://{}", domain),
            method: "CONNECT".to_string(), // HTTPS typically starts with CONNECT
            timestamp: Utc::now(),
            title: None,
            protocol: "HTTPS".to_string(),
        });
    }

    /// Prints current statistics to the log
    ///
    /// This method logs the current state of traffic monitoring,
    /// including packet counts and recent activity.
    fn log_stats(&self) {
        info!("Traffic Statistics:");
        info!("Duration: {:?}", Utc::now() - self.start_time);
        info!("Total packets: {}", self.packet_count);
        info!("DNS queries: {}", self.dns_queries.len());
        info!("HTTP requests: {}", self.http_requests.len());

        // Log recent DNS queries
        if !self.dns_queries.is_empty() {
            info!("Recent DNS queries:");
            for query in self.dns_queries.iter().rev().take(5) {
                info!("  {} - {}", query.timestamp, query.domain);
            }
        }

        // Log recent HTTP requests
        if !self.http_requests.is_empty() {
            info!("Recent HTTP requests:");
            for request in self.http_requests.iter().rev().take(5) {
                info!(
                    "  {} - {} {}",
                    request.timestamp, request.method, request.url
                );
            }
        }
    }

    /// Converts the statistics into template data for rendering
    ///
    /// # Returns
    ///
    /// A `TemplateData` structure ready for template rendering
    fn to_template_data(&self) -> TemplateData {
        TemplateData {
            start_time: self
                .start_time
                .with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
            duration: format!("{:?}", Utc::now() - self.start_time),
            packet_count: self.packet_count,
            dns_count: self.dns_queries.len(),
            http_count: self.http_requests.len(),
            http_requests: self.http_requests.clone(),
            dns_queries: self.dns_queries.clone(),
        }
    }
}

/// Monitors network traffic for a specific target
///
/// # Arguments
///
/// * `target` - IP address to monitor
/// * `interface` - Optional network interface name
/// * `output_dir` - Directory where the HTML report will be saved
///
/// # Returns
///
/// Result indicating success or containing error message
fn monitor_traffic(target: &str, interface: Option<&str>, output_dir: &str) -> Result<(), String> {
    // Initialize statistics
    let stats = Arc::new(Mutex::new(TrafficStats::new()));
    let stats_clone = Arc::clone(&stats);
    let output_dir = output_dir.to_string();

    // Start HTML update thread
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        let stats = stats_clone.lock().unwrap();
        if let Err(e) = update_html_report(&stats, &output_dir) {
            error!("Failed to update HTML report: {}", e);
        }
    });

    // Find appropriate network interface
    let device = match interface {
        Some(name) => Device::list()
            .map_err(|e| format!("Failed to list devices: {}", e))?
            .into_iter()
            .find(|d| d.name == name)
            .ok_or_else(|| format!("Interface {} not found", name))?,
        None => Device::lookup()
            .map_err(|e| format!("Failed to find default device: {}", e))?
            .ok_or_else(|| "No default device found".to_string())?,
    };

    info!("Using network interface: {}", device.name);

    // Create packet capture with specified parameters
    let mut cap = Capture::from_device(device)
        .map_err(|e| format!("Failed to create capture: {}", e))?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .map_err(|e| format!("Failed to open capture: {}", e))?;

    // Set capture filter for HTTP and DNS traffic
    let filter = format!("host {} and (port 80 or port 53 or port 443)", target);
    cap.filter(&filter, true)
        .map_err(|e| format!("Failed to set filter: {}", e))?;

    info!("Started capturing traffic with filter: {}", filter);

    // Main capture loop
    while let Ok(packet) = cap.next_packet() {
        let mut stats = stats.lock().unwrap();
        stats.packet_count += 1;

        // Analyze packet based on content
        if packet.header.len > 0 {
            if is_dns_packet(&packet.data) {
                if let Some(domain) = analyze_dns_packet(&packet.data) {
                    debug!("DNS query captured: {}", domain);
                    stats.add_dns_query(domain.clone());

                    // If this DNS query is followed by traffic on port 443, it's likely HTTPS
                    if is_https_traffic(&packet.data) {
                        stats.add_https_request(&domain);
                    }
                }
            } else if is_http_packet(&packet.data) {
                if let Some((method, url, title)) = analyze_http_packet(&packet.data) {
                    debug!("HTTP request captured: {} {}", method, url);
                    stats.add_http_request(url, method, title);
                }
            }
        }

        // Log statistics periodically
        if stats.packet_count % 100 == 0 {
            stats.log_stats();
        }
    }

    Ok(())
}

fn is_https_traffic(packet_data: &[u8]) -> bool {
    if packet_data.len() <= 40 {
        return false;
    }

    // Check for port 443
    let dest_port = ((packet_data[22] as u16) << 8) | packet_data[23] as u16;
    let src_port = ((packet_data[20] as u16) << 8) | packet_data[21] as u16;

    dest_port == 443 || src_port == 443
}

fn is_dns_packet(packet_data: &[u8]) -> bool {
    // DNS packets typically start after IP (20 bytes) and UDP (8 bytes) headers
    if packet_data.len() <= 28 {
        return false;
    }

    // Check for standard DNS port (53)
    let dest_port = ((packet_data[22] as u16) << 8) | packet_data[23] as u16;
    let src_port = ((packet_data[20] as u16) << 8) | packet_data[21] as u16;

    dest_port == 53 || src_port == 53
}

fn is_http_packet(packet_data: &[u8]) -> bool {
    if packet_data.len() <= 40 {
        return false;
    }

    let data = &packet_data[40..];
    if let Ok(str_data) = std::str::from_utf8(data) {
        let first_line = str_data.lines().next().unwrap_or("");
        return first_line.contains("HTTP/")
            || first_line.starts_with("GET ")
            || first_line.starts_with("POST ")
            || first_line.starts_with("HEAD ")
            || first_line.starts_with("PUT ")
            || first_line.starts_with("DELETE ");
    }
    false
}

/// Analyzes a DNS packet and extracts the queried domain
///
/// # Arguments
///
/// * `packet_data` - Raw packet data including IP and UDP headers
fn analyze_dns_packet(packet_data: &[u8]) -> Option<String> {
    // DNS packet should be at least 12 bytes (header) + some data
    if packet_data.len() < 12 {
        return None;
    }

    // Skip IP header (20 bytes) and UDP header (8 bytes)
    let dns_data = if packet_data.len() > 28 {
        &packet_data[28..]
    } else {
        return None;
    };

    // Basic DNS header parsing
    // Skip first 12 bytes (DNS header) and start reading labels
    let mut pos = 12;
    let mut domain = String::new();

    while pos < dns_data.len() {
        let len = dns_data[pos] as usize;
        if len == 0 {
            break;
        }

        // Prevent buffer overflow
        if pos + 1 + len > dns_data.len() {
            return None;
        }

        // Add dot between labels
        if !domain.is_empty() {
            domain.push('.');
        }

        // Extract label
        if let Ok(label) = std::str::from_utf8(&dns_data[pos + 1..pos + 1 + len]) {
            domain.push_str(label);
        } else {
            return None;
        }

        pos += len + 1;
    }

    if domain.is_empty() {
        None
    } else {
        debug!("Found DNS query for domain: {}", domain);
        Some(domain)
    }
}

/// Represents the type of HTTP protocol
#[derive(Debug, Clone)]
pub enum HttpVersion {
    Http1,
    Http2,
}

/// Analyzes an HTTP packet and extracts request information
///
/// # Arguments
///
/// * `packet_data` - Raw packet data including IP and TCP headers
fn analyze_http_packet(packet_data: &[u8]) -> Option<(String, String, Option<String>)> {
    if packet_data.len() <= 40 {
        return None;
    }

    let data = &packet_data[40..]; // Skip IP and TCP headers

    // First, try to determine the HTTP version
    match detect_http_version(data) {
        HttpVersion::Http1 => analyze_http1_packet(data),
        HttpVersion::Http2 => analyze_http2_packet(data),
    }
}

/// Detects the HTTP version from packet data
fn detect_http_version(data: &[u8]) -> HttpVersion {
    if data.len() < 24 {
        return HttpVersion::Http1;
    }

    // Check for HTTP/2 connection preface
    const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if data.starts_with(H2_PREFACE) {
        return HttpVersion::Http2;
    }

    // Default to HTTP/1.x
    HttpVersion::Http1
}

/// Analyzes HTTP/1.x packets
fn analyze_http1_packet(data: &[u8]) -> Option<(String, String, Option<String>)> {
    if let Ok(data_str) = std::str::from_utf8(data) {
        // Look for common HTTP methods
        let methods = [
            "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT",
        ];

        for method in methods.iter() {
            if data_str.starts_with(method) {
                if let Some(request_line) = data_str.lines().next() {
                    let parts: Vec<&str> = request_line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        // Extract host and construct URL
                        let host = data_str
                            .lines()
                            .find(|line| line.starts_with("Host: "))
                            .and_then(|line| Some(line.trim_start_matches("Host: ").trim()))
                            .unwrap_or("");

                        let path = parts[1];
                        let url = if host.is_empty() {
                            path.to_string()
                        } else {
                            format!("http://{}{}", host, path)
                        };

                        // Extract title if present
                        let title = extract_title(data_str);

                        debug!("HTTP/1.x request: {} {}", method, url);
                        return Some((method.to_string(), url, title));
                    }
                }
            }
        }
    }
    None
}

/// Analyzes HTTP/2 packets
fn analyze_http2_packet(data: &[u8]) -> Option<(String, String, Option<String>)> {
    const H2_PREFACE_LEN: usize = 24;
    let frame_data = if data.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        &data[H2_PREFACE_LEN..]
    } else {
        data
    };

    if frame_data.len() < 9 {
        return None;
    }

    let frame_length =
        ((frame_data[0] as u32) << 16) | ((frame_data[1] as u32) << 8) | (frame_data[2] as u32);
    let frame_type = frame_data[3];
    let _flags = frame_data[4];
    let stream_id = ((frame_data[5] as u32) << 24)
        | ((frame_data[6] as u32) << 16)
        | ((frame_data[7] as u32) << 8)
        | (frame_data[8] as u32);

    // Only process HEADERS frames (type 0x1) with complete payload
    if frame_type == 0x1 && frame_data.len() >= 9 + frame_length as usize {
        let headers_payload = &frame_data[9..9 + frame_length as usize];

        if let Some(headers) = decode_http2_headers(headers_payload) {
            let method = headers.get(":method").cloned().unwrap_or_default();
            let scheme = headers.get(":scheme").cloned().unwrap_or_default();
            let authority = headers.get(":authority").cloned().unwrap_or_default();
            let path = headers.get(":path").cloned().unwrap_or_default();

            let url = format!("{}://{}{}", scheme, authority, path);
            debug!("HTTP/2 request: {} {} (stream: {})", method, url, stream_id);

            return Some((method, url, None));
        }
    }

    None
}

fn decode_http2_headers(data: &[u8]) -> Option<HashMap<String, String>> {
    let mut headers = HashMap::new();
    let mut pos = 0;

    while pos < data.len() {
        // Read header length
        if pos + 2 > data.len() {
            break;
        }

        let length = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2;

        if pos + length > data.len() {
            break;
        }

        // Try to parse header as UTF-8 string
        if let Ok(header_str) = std::str::from_utf8(&data[pos..pos + length]) {
            if let Some(separator) = header_str.find(':') {
                let name = header_str[..separator].trim();
                let value = header_str[separator + 1..].trim();
                headers.insert(name.to_string(), value.to_string());
            }
        }

        pos += length;
    }

    if headers.is_empty() {
        None
    } else {
        Some(headers)
    }
}

fn extract_title(data: &str) -> Option<String> {
    if let Some(start) = data.to_lowercase().find("<title>") {
        if let Some(end) = data[start..].to_lowercase().find("</title>") {
            return Some(data[start + 7..start + end].trim().to_string());
        }
    }
    None
}

/// Updates the HTML report with current statistics
///
/// # Arguments
///
/// * `stats` - Current traffic statistics
/// * `output_dir` - Directory where the report should be saved
///
/// # Returns
///
/// Result indicating success or containing error message
fn update_html_report(stats: &TrafficStats, output_dir: &str) -> Result<(), String> {
    let path = Path::new(output_dir);
    if !path.exists() {
        std::fs::create_dir_all(path)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;
    }

    let mut handlebars = Handlebars::new();
    let template = include_str!("../templates/report.html");

    handlebars
        .register_template_string("report", template)
        .map_err(|e| format!("Failed to register template: {}", e))?;

    let report_path = path.join("report.html");
    let mut file =
        File::create(&report_path).map_err(|e| format!("Failed to create report file: {}", e))?;

    let template_data = stats.to_template_data();
    let rendered = handlebars
        .render("report", &template_data)
        .map_err(|e| format!("Failed to render template: {}", e))?;

    file.write_all(rendered.as_bytes())
        .map_err(|e| format!("Failed to write report: {}", e))?;

    info!("Updated report at: {}", report_path.display());
    Ok(())
}

/// Main entry point for the traffic monitoring tool
fn main() {
    // Initialize logging
    env_logger::init();

    // Parse command line arguments
    let args = Args::parse();

    info!("Starting traffic monitoring for target: {}", args.target);

    // Start monitoring
    if let Err(e) = monitor_traffic(&args.target, args.interface.as_deref(), &args.output) {
        error!("Monitoring failed: {}", e);
        std::process::exit(1);
    }
}
