//! # Traffic Monitor Binary
//!
//! A network traffic monitoring tool that captures and analyzes network packets to track
//! web browsing activity of a target host. Supports HTTP, HTTPS, and DNS traffic analysis.
//!
//! ## Operation Flow
//!
//! ```text
//! 1. Capture Setup ────┐
//!                      │
//! 2. Packet Capture ───┼──► Packet Analysis ──► State Update
//!                      │         │                    │
//! 3. Report Generation ◄─────────┴────────────────────┘
//! ```
//!
//! ## Features
//!
//! * Real-time packet capture and analysis
//! * Protocol support: HTTP, HTTPS (SNI extraction), DNS
//! * Live HTML report generation with automatic updates
//! * Timestamp-based activity tracking
//!

use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::{DateTime, Local, Utc};
use clap::Parser;
use handlebars::{Handlebars, Helper, HelperResult, Output, RenderContext};
use log::{debug, error, info};
use pcap::{Capture, Device};
use serde::Serialize;

use mitm_tools::packet_analyzer::{HttpRequest, PacketAnalyzer, PacketType};

/// Command line arguments for the traffic monitoring tool
///
/// # Example
///
/// ```text
/// traffic_monitor -t 192.168.1.100 -i eth0 -o /path/to/report
/// ```
#[derive(Parser)]
#[command(name = "traffic_monitor")]
#[command(author, version)]
#[command(about = "Network traffic monitoring tool")]
#[command(
    long_about = "A network traffic monitoring tool that captures and analyzes packets \
    to track web browsing activity of a target host.\n\
    \n\
    USAGE:\n\
      traffic_monitor -t <TARGET_IP> [-i <INTERFACE>] [-o <OUTPUT_DIR>]\n\
    \n\
    EXAMPLES:\n\
      # Monitor traffic from 192.168.1.100 using default interface\n\
      traffic_monitor -t 192.168.1.100\n\
      \n\
      # Monitor using specific interface and custom output directory\n\
      traffic_monitor -t 192.168.1.100 -i eth0 -o /path/to/output\n\
    \n\
    SUPPORTED PROTOCOLS:\n\
      - HTTP (Port 80)\n\
      - HTTPS (Port 443) with SNI extraction\n\
      - HTTP/2 (both h2 and h2c)\n\
      - DNS (Port 53)\n\
    \n\
    The tool generates an HTML report with captured traffic information that updates\n\
    every 5 seconds. The report includes:\n\
      - DNS queries\n\
      - HTTP/HTTPS requests\n\
      - Page titles when available\n\
      - Timestamps for all captured traffic"
)]
struct Args {
    /// Target IP address to monitor
    #[arg(short, long)]
    target: String,

    /// Network interface to monitor (optional, uses default if not specified)
    #[arg(short, long)]
    interface: Option<String>,

    /// Output directory for HTML report
    #[arg(short, long, default_value = "report")]
    output: String,
}

/// Represents a captured DNS query with associated timestamp
///
/// Stores information about DNS requests made by the target,
/// including the queried domain and when the query occurred.
#[derive(Debug, Clone, Serialize)]
struct DnsQuery {
    /// Domain name being queried
    domain: String,
    /// Timestamp when the query was captured
    #[serde(with = "chrono::serde::ts_seconds")]
    timestamp: DateTime<Utc>,
}

/// Data structure for the HTML template rendering
///
/// Contains all the information needed to generate the monitoring
/// report, including statistics and captured traffic details.
#[derive(Serialize)]
struct TemplateData {
    /// Session start time in local timezone
    start_time: String,
    /// Duration of the monitoring session
    duration: String,
    /// Total number of packets captured
    packet_count: usize,
    /// Number of DNS queries captured
    dns_count: usize,
    /// Number of HTTP/HTTPS requests captured
    http_count: usize,
    /// List of captured HTTP/HTTPS requests
    http_requests: Vec<HttpRequest>,
    /// List of captured DNS queries
    dns_queries: Vec<DnsQuery>,
}

/// Maintains statistics and captured data during the monitoring session
///
/// Acts as a central storage for all captured traffic information and
/// provides methods to update and access this data safely.
#[derive(Debug)]
struct TrafficStats {
    /// Captured DNS queries in chronological order
    dns_queries: Vec<DnsQuery>,
    /// Captured HTTP/HTTPS requests in chronological order
    http_requests: Vec<HttpRequest>,
    /// Total number of packets processed
    packet_count: usize,
    /// Timestamp when monitoring started
    start_time: DateTime<Utc>,
}

impl TrafficStats {
    /// Creates a new TrafficStats instance with initialized values
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
    /// Inserts the query at the beginning of the list for
    /// reverse chronological ordering in the report.
    fn add_dns_query(&mut self, domain: String) {
        self.dns_queries.insert(
            0,
            DnsQuery {
                domain,
                timestamp: Utc::now(),
            },
        );
    }

    /// Adds a new HTTP request to the statistics
    ///
    /// Performs deduplication by checking for similar requests
    /// within a 1-second window to avoid duplicates from retransmissions.
    fn add_http_request(&mut self, request: HttpRequest) {
        // Check for duplicate requests within 1 second
        if !self.http_requests.iter().any(|r| {
            r.method == request.method
                && r.url == request.url
                && (r.timestamp - request.timestamp).num_seconds().abs() < 1
        }) {
            self.http_requests.insert(0, request);
        }
    }

    /// Converts the statistics into template-ready data
    ///
    /// Formats timestamps and durations for display in the HTML report.
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

/// Main monitor structure that coordinates packet capture and analysis
struct Monitor {
    /// Shared statistics accessible from multiple threads
    stats: Arc<Mutex<TrafficStats>>,
    /// Packet analyzer instance for traffic inspection
    analyzer: PacketAnalyzer,
    /// Directory where HTML reports will be saved
    output_dir: String,
}

impl Monitor {
    /// Creates a new Monitor instance
    ///
    /// # Arguments
    ///
    /// * `target_ip` - IP address of the host to monitor
    /// * `output_dir` - Directory where reports will be saved
    pub fn new(target_ip: IpAddr, output_dir: String) -> Self {
        Self {
            stats: Arc::new(Mutex::new(TrafficStats::new())),
            analyzer: PacketAnalyzer::new(target_ip),
            output_dir,
        }
    }

    /// Configures and initializes packet capture
    ///
    /// # Arguments
    ///
    /// * `interface` - Optional network interface name
    ///
    /// # Returns
    ///
    /// Active packet capture handle or error message
    ///
    /// # Network Configuration
    ///
    /// Sets up capture with:
    /// * Promiscuous mode enabled
    /// * Maximum packet size (65535 bytes)
    /// * 1-second timeout
    /// * Filter for HTTP, HTTPS, and DNS traffic
    fn setup_capture(&self, interface: Option<&str>) -> Result<Capture<pcap::Active>, String> {
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

        let mut cap = Capture::from_device(device)
            .map_err(|e| format!("Failed to create capture: {}", e))?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()
            .map_err(|e| format!("Failed to open capture: {}", e))?;

        // Set capture filter for target's traffic only
        let filter = format!(
            "(host {}) and (port 80 or port 53 or port 443)",
            self.analyzer.get_target_ip()
        );

        cap.filter(&filter, true)
            .map_err(|e| format!("Failed to set filter: {}", e))?;

        info!("Started capturing traffic with filter: {}", filter);
        Ok(cap)
    }

    /// Starts a background thread for periodic report updates
    ///
    /// Creates an HTML report every 5 seconds with the latest statistics.
    fn start_report_updater(&self) {
        let stats = Arc::clone(&self.stats);
        let output_dir = self.output_dir.clone();

        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(5));
            if let Err(e) = update_html_report(&stats.lock().unwrap(), &output_dir) {
                error!("Failed to update HTML report: {}", e);
            }
        });
    }

    /// Starts the monitoring process
    ///
    /// # Arguments
    ///
    /// * `interface` - Optional network interface name
    ///
    /// # Returns
    ///
    /// Success or error message
    pub fn start(&mut self, interface: Option<&str>) -> Result<(), String> {
        let mut cap = self.setup_capture(interface)?;
        self.start_report_updater();

        while let Ok(packet) = cap.next_packet() {
            let packet_type = self.analyzer.analyze_packet(&packet.data);
            self.process_packet(packet_type);
        }

        Ok(())
    }

    /// Processes a captured packet and updates statistics
    ///
    /// # Arguments
    ///
    /// * `packet_type` - Analyzed packet type and contents
    fn process_packet(&self, packet_type: PacketType) {
        let mut stats = self.stats.lock().unwrap();
        stats.packet_count += 1;

        match packet_type {
            PacketType::DNS(domain) => {
                info!("DNS Query: {}", domain);
                stats.add_dns_query(domain);
            }
            PacketType::HTTP(request) => {
                info!(
                    "HTTP Request: {} {} ({})",
                    request.method, request.url, request.protocol
                );
                stats.add_http_request(request);
            }
            PacketType::HTTPS(domain) => {
                info!("HTTPS Connection to: {}", domain);
                stats.add_http_request(HttpRequest {
                    method: "CONNECT".to_string(),
                    url: format!("https://{}", domain),
                    title: None,
                    protocol: "HTTPS".to_string(),
                    timestamp: Utc::now(),
                });
            }
            PacketType::Unknown => {
                debug!("Unknown packet type");
            }
        }
    }
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
/// Success or error message
fn update_html_report(stats: &TrafficStats, output_dir: &str) -> Result<(), String> {
    let path = Path::new(output_dir);
    if !path.exists() {
        std::fs::create_dir_all(path)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;
    }

    let mut handlebars = Handlebars::new();

    // Register helper for timestamp formatting
    handlebars.register_helper(
        "format_timestamp",
        Box::new(
            |h: &Helper,
             _: &Handlebars,
             _: &handlebars::Context,
             _: &mut RenderContext,
             out: &mut dyn Output|
             -> HelperResult {
                let timestamp = h.param(0).and_then(|v| v.value().as_i64()).unwrap_or(0);
                let dt = DateTime::<Utc>::from_timestamp(timestamp, 0)
                    .unwrap_or_default()
                    .with_timezone(&Local);
                out.write(&dt.format("%Y-%m-%d %H:%M:%S").to_string())?;
                Ok(())
            },
        ),
    );

    // Register helper for duration formatting
    handlebars.register_helper(
        "format_duration",
        Box::new(
            |h: &Helper,
             _: &Handlebars,
             _: &handlebars::Context,
             _: &mut RenderContext,
             out: &mut dyn Output|
             -> HelperResult {
                let duration = h.param(0).and_then(|v| v.value().as_str()).unwrap_or("");
                let formatted = duration.replace("TimeDelta { ", "").replace(" }", "");
                out.write(&formatted)?;
                Ok(())
            },
        ),
    );

    // Register helper for protocol comparison
    handlebars.register_helper(
        "eq",
        Box::new(
            |h: &Helper,
             _: &Handlebars,
             _: &handlebars::Context,
             _: &mut RenderContext,
             out: &mut dyn Output|
             -> HelperResult {
                let param0 = h.param(0).and_then(|v| v.value().as_str()).unwrap_or("");
                let param1 = h.param(1).and_then(|v| v.value().as_str()).unwrap_or("");
                out.write(if param0 == param1 { "true" } else { "false" })?;
                Ok(())
            },
        ),
    );

    let template = include_str!("../templates/report.html");

    handlebars
        .register_template_string("report", template)
        .map_err(|e| format!("Failed to register template: {}", e))?;

    let report_path = path.join("report.html");
    let file = std::fs::File::create(&report_path)
        .map_err(|e| format!("Failed to create report file: {}", e))?;

    let template_data = stats.to_template_data();
    handlebars
        .render_to_write("report", &template_data, file)
        .map_err(|e| format!("Failed to render template: {}", e))?;

    info!("Updated report at: {}", report_path.display());
    Ok(())
}

/// Main entry point for the traffic monitoring tool
///
/// Initializes logging, parses command line arguments, and starts
/// the monitoring process. Exits with status code 1 if an error occurs.
fn main() {
    env_logger::init();
    let args = Args::parse();

    let target_ip = args.target.parse().expect("Invalid target IP address");

    let mut monitor = Monitor::new(target_ip, args.output);

    if let Err(e) = monitor.start(args.interface.as_deref()) {
        error!("Monitoring failed: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_traffic_stats_new() {
        let stats = TrafficStats::new();
        assert!(stats.dns_queries.is_empty());
        assert!(stats.http_requests.is_empty());
        assert_eq!(stats.packet_count, 0);
    }

    #[test]
    fn test_add_dns_query() {
        let mut stats = TrafficStats::new();
        stats.add_dns_query("example.com".to_string());

        assert_eq!(stats.dns_queries.len(), 1);
        assert_eq!(stats.dns_queries[0].domain, "example.com");
    }

    #[test]
    fn test_add_http_request() {
        let mut stats = TrafficStats::new();
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "http://example.com".to_string(),
            title: None,
            protocol: "HTTP/1".to_string(),
            timestamp: Utc::now(),
        };

        stats.add_http_request(request.clone());
        assert_eq!(stats.http_requests.len(), 1);
        assert_eq!(stats.http_requests[0].url, "http://example.com");

        // Test deduplication within 1 second
        stats.add_http_request(request);
        assert_eq!(stats.http_requests.len(), 1);
    }

    #[test]
    fn test_template_data_conversion() {
        let mut stats = TrafficStats::new();
        stats.add_dns_query("example.com".to_string());
        stats.packet_count = 10;

        let template_data = stats.to_template_data();
        assert_eq!(template_data.packet_count, 10);
        assert_eq!(template_data.dns_count, 1);
        assert_eq!(template_data.http_count, 0);
    }

    #[test]
    fn test_monitor_creation() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let monitor = Monitor::new(ip, "test_output".to_string());

        assert_eq!(monitor.output_dir, "test_output");
        // Verify initial state of stats
        let stats = monitor.stats.lock().unwrap();
        assert_eq!(stats.packet_count, 0);
    }

    #[test]
    fn test_process_packet() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let monitor = Monitor::new(ip, "test_output".to_string());

        // Test DNS packet processing
        monitor.process_packet(PacketType::DNS("example.com".to_string()));
        let stats = monitor.stats.lock().unwrap();
        assert_eq!(stats.dns_queries.len(), 1);
        assert_eq!(stats.packet_count, 1);

        // Test HTTP packet processing
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "http://example.com".to_string(),
            title: None,
            protocol: "HTTP/1".to_string(),
            timestamp: Utc::now(),
        };
        drop(stats); // Release the lock before next use

        monitor.process_packet(PacketType::HTTP(request));
        let stats = monitor.stats.lock().unwrap();
        assert_eq!(stats.http_requests.len(), 1);
        assert_eq!(stats.packet_count, 2);
    }

    #[test]
    fn test_handlebars_helpers() {
        // Test timestamp formatting
        let mut handlebars = Handlebars::new();
        handlebars.register_helper(
            "format_timestamp",
            Box::new(
                |h: &Helper,
                 _: &Handlebars,
                 _: &handlebars::Context,
                 _: &mut RenderContext,
                 out: &mut dyn Output|
                 -> HelperResult {
                    let timestamp = h.param(0).and_then(|v| v.value().as_i64()).unwrap_or(0);
                    let dt = DateTime::<Utc>::from_timestamp(timestamp, 0)
                        .unwrap_or_default()
                        .with_timezone(&Local);
                    out.write(&dt.format("%Y-%m-%d %H:%M:%S").to_string())?;
                    Ok(())
                },
            ),
        );

        let template = "{{format_timestamp 1632144000}}";
        let result = handlebars.render_template(template, &()).unwrap();
        assert!(!result.is_empty());
    }
}
