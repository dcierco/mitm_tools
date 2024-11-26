# 🕵️‍♂️ MITM Tools

A powerful network monitoring (Blazingly fast. In rust btw) and man-in-the-middle analysis toolkit written in Rust. Designed for network security testing and traffic analysis in controlled environments.

## 🚀 Features

- 🔍 **Host Discovery**: Fast network scanning using ICMP
- 📡 **Traffic Monitoring**: Real-time packet capture and analysis
- 🌐 **Protocol Support**:
  - HTTP/1.x and HTTP/2
  - HTTPS with SNI extraction
  - DNS query tracking
- 📊 **Live Reporting**: Beautiful web interface with real-time updates
- 🔒 **Security First**: Built-in target validation and filtering

## 🛠️ Installation

### Prerequisites
- libpcap-dev (for packet capture)
- Root/Administrator privileges (for raw sockets)

### Building from Source
```bash
git clone https://github.com/dcierco/mitm_tools
cd mitm_tools
cargo build --release
```

## 🐳 Docker Setup

The project includes Docker support for easy testing:

```bash
# Build and start containers
docker-compose up -d

# Install dependencies in target container
docker exec -it target apt-get update && apt-get install -y curl

# Build tools in attacker container
docker exec -it attacker cargo build --release
```

## 🎮 Usage

### Host Discovery
```bash
# Scan local network
./target/release/host_discovery -n 192.168.1.0/24

# Custom timeout
./target/release/host_discovery -n 192.168.1.0/24 -t 2000
```

### Traffic Monitoring
```bash
# Monitor specific target
./target/release/traffic_monitor -t 192.168.1.100

# With custom interface and output directory
./target/release/traffic_monitor -t 192.168.1.100 -i eth0 -o /path/to/reports
```

## 🧪 Testing Environment

The project includes a complete testing environment with Docker:
- Target container (Ubuntu-based)
- Attacker container (Rust-based)
- Isolated network for safe testing
- Pre-configured network settings

### Network Setup
```
┌─────────────┐         ┌─────────────┐
│   Target    │         │  Attacker   │
│172.18.0.2   ├─────────┤ 172.18.0.3  │
└─────────────┘         └─────────────┘
```

## 📊 Report Interface

The traffic monitor generates a live HTML report including:
- Active session statistics
- DNS query history
- HTTP/HTTPS requests
- Page titles (when available)
- Protocol information
- Timestamps for all events

## 🔒 Security Notice

This toolkit is intended for:
- Educational purposes
- Authorized security testing
- Network troubleshooting

**Do not** use these tools on networks or systems without explicit permission.

## 👥 Contributors

- Daniel Cierco
- Josue Nascimento

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📚 Documentation

For detailed documentation, run:
```bash
cargo doc --no-deps --open
```
