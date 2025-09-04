# Network Scanner & Monitoring Tool

## Overview

A comprehensive Python-based network scanning and monitoring tool designed for IT support engineers, network administrators, and security professionals. This tool provides powerful network discovery, port scanning, service detection, and continuous monitoring capabilities with an intuitive command-line interface.

### Key Features

- **Network Discovery**: Automated host discovery using ping sweeps across network ranges
- **Port Scanning**: TCP/UDP port scanning with service detection
- **OS Detection**: Basic operating system fingerprinting based on open services
- **Web Service Checking**: HTTP/HTTPS service availability and response analysis
- **Network Monitoring**: Continuous monitoring with alerting capabilities
- **Multi-threaded**: High-performance concurrent scanning
- **Configurable**: YAML-based configuration for easy customization
- **Comprehensive Reporting**: Detailed JSON output and console reporting
- **Cross-platform**: Works on Linux, Windows, and macOS

## Technologies Used

- **Python 3.7+**: Core programming language
- **ping3**: Cross-platform ping functionality
- **requests**: HTTP service checking
- **PyYAML**: Configuration file parsing
- **socket**: Low-level network operations
- **threading & concurrent.futures**: Multi-threaded scanning
- **ipaddress**: IP address and network handling
- **argparse**: Command-line interface

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager
- Network access for scanning

### Quick Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Preetham1725/network-scanner-toolkit.git
   cd network-scanner-toolkit
   ```

2. **Install dependencies:**
   ```bash
   pip install -r network-requirements.txt
   ```

3. **Configure settings:**
   ```bash
   # Edit network_config.yaml with your preferred settings
   nano network_config.yaml
   ```

## Configuration

Edit `network_config.yaml` to customize scanning parameters:

```yaml
# Network scanning settings
network:
  default_range: "192.168.1.0/24"     # Default network range
  timeout: 1                          # Timeout in seconds
  max_threads: 50                     # Concurrent threads

# Port scanning configuration
ports:
  common_tcp: [21, 22, 23, 25, 53, 80, 443, 3389]  # TCP ports
  common_udp: [53, 67, 68, 123, 161]               # UDP ports

# Monitoring settings
monitoring:
  interval: 300                       # Check interval (5 minutes)
  alert_threshold: 5                  # Failure threshold for alerts
```

## Usage

### Basic Network Discovery

```bash
# Scan entire network range
python network_scanner.py --scan 192.168.1.0/24

# Scan custom network range
python network_scanner.py --scan 10.0.0.0/16
```

### Port Scanning

```bash
# Scan common ports on specific host
python network_scanner.py --host 192.168.1.100

# Scan specific ports
python network_scanner.py --host 192.168.1.100 --ports 22,80,443,3389

# Comprehensive scan (discovery + port scan + service detection)
python network_scanner.py --comprehensive 192.168.1.0/24
```

### Network Monitoring

```bash
# Monitor multiple hosts continuously
python network_scanner.py --monitor 192.168.1.1,192.168.1.100,google.com

# Save results to file
python network_scanner.py --scan 192.168.1.0/24 --output network_scan.json
```

### Example Output

```
Scanning network: 192.168.1.0/24
Found active host: 192.168.1.1 (2.5ms)
Found active host: 192.168.1.100 (1.8ms)
Found active host: 192.168.1.150 (3.2ms)

Scanning ports on 192.168.1.1...
192.168.1.1:22/tcp - ssh
192.168.1.1:80/tcp - http
192.168.1.1:443/tcp - https

SCAN SUMMARY
Target: 192.168.1.0/24
Hosts found: 3
Open ports found: 15
Common services: [('http', 3), ('ssh', 2), ('https', 2)]
```

## Features in Detail

### Network Discovery
- **CIDR Support**: Scan any network range using CIDR notation
- **Concurrent Pinging**: Multi-threaded ping sweeps for fast discovery
- **Response Time Measurement**: Latency tracking for each host
- **Error Handling**: Robust error handling for network issues

### Port Scanning
- **TCP/UDP Support**: Scan both TCP and UDP ports
- **Service Detection**: Automatic service identification
- **Customizable Port Lists**: Configure common and custom port lists
- **Performance Optimized**: Concurrent scanning with timeout controls

### Monitoring & Alerting
- **Continuous Monitoring**: Real-time host availability monitoring
- **Configurable Intervals**: Customizable check frequencies
- **Alert Thresholds**: Configurable failure thresholds
- **Uptime Reporting**: Detailed uptime statistics and reports

### Web Service Analysis
- **HTTP/HTTPS Checking**: Web service availability testing
- **Response Time Tracking**: Performance monitoring
- **SSL Verification**: Certificate validation
- **Header Analysis**: Server and content type detection

## Skill Highlights

This project demonstrates expertise in:

- **Network Engineering**: TCP/IP networking, port scanning, service detection
- **Python Programming**: Object-oriented design, concurrency, error handling
- **System Administration**: Network monitoring, service management
- **Security Analysis**: Network reconnaissance, vulnerability assessment
- **Performance Optimization**: Multi-threading, concurrent processing
- **Configuration Management**: YAML-based configuration systems
- **CLI Development**: User-friendly command-line interfaces
- **Logging & Monitoring**: Professional logging and alerting systems

## Future Enhancements

- [ ] **GUI Interface**: Desktop application with visual network maps
- [ ] **Database Integration**: Store scan history in SQLite/PostgreSQL
- [ ] **Advanced OS Detection**: Enhanced fingerprinting techniques
- [ ] **Vulnerability Scanning**: Integration with CVE databases
- [ ] **Network Mapping**: Visual topology discovery and mapping
- [ ] **API Integration**: REST API for external system integration
- [ ] **Docker Support**: Containerized deployment options
- [ ] **Notification Systems**: Email, Slack, Teams integration
- [ ] **Performance Analytics**: Historical performance trending
- [ ] **Custom Plugins**: Extensible scanning modules

## Advanced Usage

### Custom Configuration Files

```bash
# Use custom configuration
python network_scanner.py --config custom_network.yaml --scan 172.16.0.0/12
```

### Automated Monitoring Scripts

```bash
#!/bin/bash
# Continuous monitoring script
while true; do
    python network_scanner.py --scan 192.168.1.0/24 --output "scan_$(date +%Y%m%d_%H%M%S).json"
    sleep 3600  # Run every hour
done
```

### Integration with System Monitoring

```python
# Example integration with monitoring systems
import subprocess
import json

result = subprocess.run(['python', 'network_scanner.py', '--scan', '192.168.1.0/24', '--output', 'temp.json'], 
                       capture_output=True, text=True)
with open('temp.json', 'r') as f:
    scan_data = json.load(f)
    
# Process results for monitoring system
for host in scan_data.get('results', []):
    if host['status'] == 'alive':
        print(f"Host {host['host']} is up with {host['response_time']}ms latency")
```

## Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=network_scanner --cov-report=html
```

## Project Structure

```
network-scanner-toolkit/
├── network_scanner.py          # Main scanner application
├── network_config.yaml        # Configuration file
├── network-requirements.txt   # Python dependencies
├── README.md                  # This documentation
├── LICENSE                    # MIT License
├── .gitignore                # Git ignore rules
├── tests/                    # Unit tests
│   ├── __init__.py
│   ├── test_scanner.py
│   └── test_monitoring.py
├── examples/                 # Usage examples
│   ├── basic_scan.py
│   ├── monitoring_script.py
│   └── custom_config.yaml
└── docs/                     # Additional documentation
    ├── installation.md
    ├── configuration.md
    └── api_reference.md
```

## Important Notes

### Security Considerations
- Always obtain proper authorization before scanning networks
- Some features may require elevated privileges (root/administrator)
- Respect rate limits and avoid overwhelming target systems
- Be aware of legal implications of network scanning

### Performance Tips
- Adjust thread counts based on system capabilities
- Use appropriate timeout values for your network
- Consider network bandwidth when scanning large ranges
- Monitor system resources during intensive scans

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/NetworkMapping`)
3. Commit your changes (`git commit -m 'Add network topology mapping'`)
4. Push to the branch (`git push origin feature/NetworkMapping`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 coding standards
- Add unit tests for new features
- Update documentation for changes
- Test on multiple platforms when possible



## Me

**Preetham L**
- Position: DA II @ Amazon
- Location: Bangalore, India
- GitHub: [@Preetham1725](https://github.com/Preetham1725)
- LinkedIn: [preetham-l-820bb8170](https://linkedin.com/in/preetham-l-820bb8170)

## Acknowledgments

- Built for IT professionals, network administrators, and security analysts


---

**Star this repository if it helped with your network administration tasks!**
**Remember**: Always use responsibly and with proper authorization!
**Have feature requests?** Open an issue or contribute to the project!
