//! Traffic Monitor Binary
//!
//! This binary provides functionality for monitoring network traffic,
//! specifically focusing on HTTP and DNS traffic for a target host.
//! It generates a live-updating HTML report of browsing history.

use chrono::serde::ts_seconds;
use chrono::{DateTime, Local, Utc};
use clap::Parser;
use core::str;
use dns_parser::Packet as DnsPacket;
use handlebars::Handlebars;
use httparse::{Request, EMPTY_HEADER};
use log::{debug, error, info};
use pcap::{Capture, Device};
use serde::Serialize;
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
    let filter = format!("host {} and (port 80 or port 53)", target);
    cap.filter(&filter, true)
        .map_err(|e| format!("Failed to set filter: {}", e))?;

    info!("Started capturing traffic with filter: {}", filter);

    // Main capture loop
    while let Ok(packet) = cap.next_packet() {
        let mut stats = stats.lock().unwrap();
        stats.packet_count += 1;

        // Analyze packet based on port number
        if packet.header.len > 0 {
            match packet.header.caplen as u16 {
                53 => {
                    // DNS packet analysis
                    if let Some(domain) = analyze_dns_packet(&packet.data) {
                        stats.add_dns_query(domain);
                    }
                }
                80 => {
                    // HTTP packet analysis
                    if let Some((method, url, title)) = analyze_http_packet(&packet.data) {
                        stats.add_http_request(url, method, title);
                    }
                }
                _ => debug!(
                    "Captured packet on unexpected port: {}",
                    packet.header.caplen
                ),
            }
        }

        // Log statistics periodically
        if stats.packet_count % 100 == 0 {
            stats.log_stats();
        }
    }

    Ok(())
}

/// Analyzes a DNS packet and extracts the queried domain
///
/// # Arguments
///
/// * `packet_data` - Raw packet data including IP and UDP headers
///
/// # Returns
///
/// Option containing the queried domain name if successfully parsed
fn analyze_dns_packet(packet_data: &[u8]) -> Option<String> {
    // Option 1: Using dns-parser crate
    fn analyze_with_dns_parser(data: &[u8]) -> Option<String> {
        // Skip IP header (20 bytes) and UDP header (8 bytes)
        let dns_data = &data[28..];

        match DnsPacket::parse(dns_data) {
            Ok(packet) => {
                // Look for the first question in the DNS query
                packet
                    .questions
                    .first()
                    .map(|question| question.qname.to_string())
            }
            Err(e) => {
                debug!("Failed to parse DNS packet: {}", e);
                None
            }
        }
    }

    // Option 2: Manual DNS header parsing
    fn analyze_manually(data: &[u8]) -> Option<String> {
        if data.len() < 30 {
            // Minimum size for headers + some DNS data
            return None;
        }

        let dns_data = &data[28..]; // Skip IP and UDP headers
        let mut domain = String::new();
        let mut pos = 12; // Skip DNS header

        while pos < dns_data.len() {
            let len = dns_data[pos] as usize;
            if len == 0 {
                break;
            }

            pos += 1;
            if pos + len > dns_data.len() {
                return None;
            }

            if !domain.is_empty() {
                domain.push('.');
            }

            if let Ok(label) = str::from_utf8(&dns_data[pos..pos + len]) {
                domain.push_str(label);
            } else {
                return None;
            }

            pos += len;
        }

        if domain.is_empty() {
            None
        } else {
            Some(domain)
        }
    }

    // Try dns-parser first, fall back to manual parsing
    analyze_with_dns_parser(packet_data).or_else(|| analyze_manually(packet_data))
}

/// Analyzes an HTTP packet and extracts request information
///
/// # Arguments
///
/// * `packet_data` - Raw packet data including IP and TCP headers
///
/// # Returns
///
/// Option containing tuple of (method, url, title) if successfully parsed
fn analyze_http_packet(packet_data: &[u8]) -> Option<(String, String, Option<String>)> {
    // Option 1: Using httparse crate
    fn analyze_with_httparse(data: &[u8]) -> Option<(String, String, Option<String>)> {
        let mut headers = [EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers);

        // Skip IP header (20 bytes) and TCP header (20 bytes)
        let http_data = &data[40..];

        match req.parse(http_data) {
            Ok(status) if status.is_complete() => {
                let method = req.method?.to_string();
                let path = req.path?.to_string();

                // Try to find Host header to construct full URL
                let host = headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("Host"))
                    .and_then(|h| str::from_utf8(h.value).ok())
                    .unwrap_or("");

                let url = if host.is_empty() {
                    path
                } else {
                    format!("http://{}{}", host, path)
                };

                // Look for title in response body
                let title = extract_title_from_body(http_data);

                Some((method, url, title))
            }
            _ => None,
        }
    }

    // Option 2: Manual HTTP parsing
    fn analyze_manually(data: &[u8]) -> Option<(String, String, Option<String>)> {
        let http_data = &data[40..]; // Skip IP and TCP headers

        // Convert to string and split into lines
        if let Ok(text) = str::from_utf8(http_data) {
            let lines: Vec<&str> = text.lines().collect();
            if let Some(request_line) = lines.first() {
                let parts: Vec<&str> = request_line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let method = parts[0].to_string();
                    let path = parts[1].to_string();

                    // Try to find Host header
                    let host = lines
                        .iter()
                        .find(|line| line.starts_with("Host: "))
                        .and_then(|line| Some(line[6..].trim()))
                        .unwrap_or("");

                    let url = if host.is_empty() {
                        path
                    } else {
                        format!("http://{}{}", host, path)
                    };

                    return Some((method, url, None));
                }
            }
        }
        None
    }

    // Helper function to extract title from HTML
    fn extract_title_from_body(data: &[u8]) -> Option<String> {
        if let Ok(text) = str::from_utf8(data) {
            if let Some(start) = text.to_lowercase().find("<title>") {
                if let Some(end) = text[start..].to_lowercase().find("</title>") {
                    let title_content = &text[start + 7..start + end].trim();
                    return Some(title_content.to_string());
                }
            }
        }
        None
    }

    // Try httparse first, fall back to manual parsing
    analyze_with_httparse(packet_data).or_else(|| analyze_manually(packet_data))
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
