// src/bin/traffic_monitor.rs

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
    domain: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    timestamp: DateTime<Utc>,
}

/// Structure for passing data to the HTML template
#[derive(Serialize)]
struct TemplateData {
    start_time: String,
    duration: String,
    packet_count: usize,
    dns_count: usize,
    http_count: usize,
    http_requests: Vec<HttpRequest>,
    dns_queries: Vec<DnsQuery>,
}

/// Structure to store traffic statistics and captured data
#[derive(Debug)]
struct TrafficStats {
    dns_queries: Vec<DnsQuery>,
    http_requests: Vec<HttpRequest>,
    packet_count: usize,
    start_time: DateTime<Utc>,
}

impl TrafficStats {
    fn new() -> Self {
        TrafficStats {
            dns_queries: Vec::new(),
            http_requests: Vec::new(),
            packet_count: 0,
            start_time: Utc::now(),
        }
    }

    fn add_dns_query(&mut self, domain: String) {
        self.dns_queries.push(DnsQuery {
            domain,
            timestamp: Utc::now(),
        });
    }

    fn add_http_request(&mut self, request: HttpRequest) {
        self.http_requests.push(request);
    }

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

struct Monitor {
    stats: Arc<Mutex<TrafficStats>>,
    analyzer: PacketAnalyzer,
    output_dir: String,
}

impl Monitor {
    pub fn new(target_ip: IpAddr, output_dir: String) -> Self {
        Self {
            stats: Arc::new(Mutex::new(TrafficStats::new())),
            analyzer: PacketAnalyzer::new(target_ip),
            output_dir,
        }
    }

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

        // Modify the filter to only capture target's traffic
        let filter = format!(
            "(host {}) and (port 80 or port 53 or port 443)",
            self.analyzer.get_target_ip()
        );

        cap.filter(&filter, true)
            .map_err(|e| format!("Failed to set filter: {}", e))?;

        info!("Started capturing traffic with filter: {}", filter);
        Ok(cap)
    }

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

    pub fn start(&mut self, interface: Option<&str>) -> Result<(), String> {
        let mut cap = self.setup_capture(interface)?;
        self.start_report_updater();

        while let Ok(packet) = cap.next_packet() {
            let packet_type = self.analyzer.analyze_packet(&packet.data);
            self.process_packet(packet_type);
        }

        Ok(())
    }

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
