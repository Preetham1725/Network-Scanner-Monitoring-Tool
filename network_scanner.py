
#!/usr/bin/env python3
"""
Network Scanner & Monitoring Tool
Author: Preetham L
Description: Network discovery, port scanning, and monitoring utilities for IT Support Engineers
Features: Host discovery, port scanning, network monitoring, service detection
"""

import socket
import threading
import subprocess
import ipaddress
import time
import json
import yaml
import logging
import argparse
import ping3
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
import platform
import os

class NetworkScanner:
    """
    Comprehensive network scanning and monitoring tool.
    
    Features:
    - Host discovery (ping sweep)
    - Port scanning (TCP/UDP)
    - Service detection
    - Network monitoring
    - Latency monitoring
    - Service availability checking
    """
    
    def __init__(self, config_file: str = 'network_config.yaml'):
        """
        Initialize the network scanner with configuration.
        
        Args:
            config_file (str): Path to the configuration file
        """
        self.config_file = config_file
        self.config = self._load_config()
        self._setup_logging()
        self.results = {}
        
    def _load_config(self) -> Dict:
        """Load configuration from YAML file."""
        try:
            with open(self.config_file, 'r') as file:
                config = yaml.safe_load(file)
                return config
        except FileNotFoundError:
            print(f"Config file {self.config_file} not found. Using default settings.")
            return self._get_default_config()
        except yaml.YAMLError as e:
            print(f"Error parsing config file: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Return default configuration if config file is not available."""
        return {
            'network': {
                'default_range': '192.168.1.0/24',
                'timeout': 1,
                'max_threads': 50
            },
            'ports': {
                'common_tcp': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306],
                'common_udp': [53, 67, 68, 123, 161, 162],
                'custom': []
            },
            'monitoring': {
                'interval': 300,  # 5 minutes
                'alert_threshold': 5,  # 5 failed attempts
                'log_file': 'network_monitor.log'
            },
            'services': {
                'web_services': ['http://', 'https://'],
                'check_ssl': True,
                'user_agent': 'NetworkScanner/1.0'
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['monitoring']['log_file']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def ping_host(self, host: str) -> Dict:
        """
        Ping a single host to check if it's alive.
        
        Args:
            host (str): IP address or hostname to ping
            
        Returns:
            Dict: Ping results including status and response time
        """
        try:
            # Use ping3 library for cross-platform compatibility
            response_time = ping3.ping(host, timeout=self.config['network']['timeout'])
            
            if response_time is not None:
                return {
                    'host': host,
                    'status': 'alive',
                    'response_time': round(response_time * 1000, 2),  # Convert to ms
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            else:
                return {
                    'host': host,
                    'status': 'dead',
                    'response_time': None,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
        except Exception as e:
            return {
                'host': host,
                'status': 'error',
                'response_time': None,
                'error': str(e),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def scan_network(self, network_range: str) -> List[Dict]:
        """
        Perform network discovery by scanning a range of IP addresses.
        
        Args:
            network_range (str): Network range in CIDR notation (e.g., 192.168.1.0/24)
            
        Returns:
            List[Dict]: List of discovered hosts with their status
        """
        self.logger.info(f"Starting network scan for {network_range}")
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            alive_hosts = []
            
            # Use ThreadPoolExecutor for concurrent pinging
            with ThreadPoolExecutor(max_workers=self.config['network']['max_threads']) as executor:
                # Submit ping tasks for all hosts in the network
                future_to_host = {
                    executor.submit(self.ping_host, str(ip)): str(ip) 
                    for ip in network.hosts()
                }
                
                # Collect results as they complete
                for future in as_completed(future_to_host):
                    result = future.result()
                    if result['status'] == 'alive':
                        alive_hosts.append(result)
                        print(f"Found active host: {result['host']} ({result['response_time']}ms)")
                    elif result['status'] == 'error':
                        self.logger.warning(f"Error pinging {result['host']}: {result.get('error', 'Unknown error')}")
            
            self.logger.info(f"Network scan completed. Found {len(alive_hosts)} active hosts")
            return sorted(alive_hosts, key=lambda x: ipaddress.ip_address(x['host']))
            
        except Exception as e:
            self.logger.error(f"Error scanning network {network_range}: {e}")
            return []
    
    def scan_port(self, host: str, port: int, protocol: str = 'tcp') -> Dict:
        """
        Scan a single port on a host.
        
        Args:
            host (str): Target host IP or hostname
            port (int): Port number to scan
            protocol (str): Protocol to use ('tcp' or 'udp')
            
        Returns:
            Dict: Port scan results
        """
        try:
            if protocol.lower() == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config['network']['timeout'])
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    # Try to get service name
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except OSError:
                        service = 'unknown'
                    
                    return {
                        'host': host,
                        'port': port,
                        'protocol': 'tcp',
                        'status': 'open',
                        'service': service,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                else:
                    return {
                        'host': host,
                        'port': port,
                        'protocol': 'tcp',
                        'status': 'closed',
                        'service': None,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
            
            elif protocol.lower() == 'udp':
                # UDP scanning is more complex and less reliable
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.config['network']['timeout'])
                
                try:
                    sock.sendto(b'', (host, port))
                    sock.recvfrom(1024)
                    status = 'open'
                except socket.timeout:
                    status = 'open|filtered'  # Common UDP response
                except ConnectionRefusedError:
                    status = 'closed'
                except Exception:
                    status = 'filtered'
                
                sock.close()
                
                try:
                    service = socket.getservbyport(port, 'udp')
                except OSError:
                    service = 'unknown'
                
                return {
                    'host': host,
                    'port': port,
                    'protocol': 'udp',
                    'status': status,
                    'service': service,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
        except Exception as e:
            return {
                'host': host,
                'port': port,
                'protocol': protocol,
                'status': 'error',
                'service': None,
                'error': str(e),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def scan_ports(self, host: str, ports: List[int], protocol: str = 'tcp') -> List[Dict]:
        """
        Scan multiple ports on a single host.
        
        Args:
            host (str): Target host IP or hostname
            ports (List[int]): List of ports to scan
            protocol (str): Protocol to use ('tcp' or 'udp')
            
        Returns:
            List[Dict]: List of port scan results
        """
        self.logger.info(f"Scanning {len(ports)} {protocol.upper()} ports on {host}")
        
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {
                executor.submit(self.scan_port, host, port, protocol): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result['status'] == 'open':
                    open_ports.append(result)
                    print(f"🔓 {host}:{result['port']}/{result['protocol']} - {result['service']}")
        
        return open_ports
    
    def detect_os(self, host: str) -> Dict:
        """
        Attempt to detect the operating system of a host.
        
        Args:
            host (str): Target host IP or hostname
            
        Returns:
            Dict: OS detection results
        """
        try:
            # Simple OS detection based on TTL values and common services
            ping_result = self.ping_host(host)
            
            if ping_result['status'] != 'alive':
                return {'host': host, 'os': 'unknown', 'confidence': 0}
            
            # Check common Windows ports
            windows_ports = [135, 139, 445, 3389]
            windows_score = 0
            
            for port in windows_ports:
                result = self.scan_port(host, port)
                if result['status'] == 'open':
                    windows_score += 1
            
            # Check common Linux/Unix ports
            linux_ports = [22, 23, 25, 80, 443]
            linux_score = 0
            
            for port in linux_ports:
                result = self.scan_port(host, port)
                if result['status'] == 'open':
                    linux_score += 1
            
            # Simple heuristic
            if windows_score > linux_score:
                return {
                    'host': host,
                    'os': 'Windows',
                    'confidence': min(windows_score / len(windows_ports) * 100, 90),
                    'details': f'Windows services detected: {windows_score}/{len(windows_ports)}'
                }
            elif linux_score > 0:
                return {
                    'host': host,
                    'os': 'Linux/Unix',
                    'confidence': min(linux_score / len(linux_ports) * 100, 80),
                    'details': f'Unix-like services detected: {linux_score}/{len(linux_ports)}'
                }
            else:
                return {
                    'host': host,
                    'os': 'Unknown',
                    'confidence': 0,
                    'details': 'No common services detected'
                }
                
        except Exception as e:
            return {
                'host': host,
                'os': 'error',
                'confidence': 0,
                'error': str(e)
            }
    
    def check_web_service(self, url: str) -> Dict:
        """
        Check if a web service is available and get basic information.
        
        Args:
            url (str): URL to check
            
        Returns:
            Dict: Web service status and information
        """
        try:
            headers = {'User-Agent': self.config['services']['user_agent']}
            
            start_time = time.time()
            response = requests.get(url, headers=headers, timeout=10, verify=self.config['services']['check_ssl'])
            response_time = round((time.time() - start_time) * 1000, 2)
            
            return {
                'url': url,
                'status': 'available',
                'status_code': response.status_code,
                'response_time': response_time,
                'server': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'content_length': len(response.content),
                'ssl_enabled': url.startswith('https://'),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except requests.exceptions.SSLError:
            return {
                'url': url,
                'status': 'ssl_error',
                'error': 'SSL certificate verification failed',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except requests.exceptions.Timeout:
            return {
                'url': url,
                'status': 'timeout',
                'error': 'Connection timeout',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except requests.exceptions.ConnectionError:
            return {
                'url': url,
                'status': 'connection_error',
                'error': 'Connection refused or host unreachable',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            return {
                'url': url,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def monitor_network(self, hosts: List[str], duration: int = 3600):
        """
        Continuously monitor network hosts for availability.
        
        Args:
            hosts (List[str]): List of hosts to monitor
            duration (int): Monitoring duration in seconds
        """
        self.logger.info(f"Starting network monitoring for {len(hosts)} hosts")
        self.logger.info(f"Monitoring duration: {duration} seconds")
        
        start_time = time.time()
        monitoring_data = {host: {'checks': 0, 'failures': 0, 'avg_response_time': 0} for host in hosts}
        
        try:
            while (time.time() - start_time) < duration:
                for host in hosts:
                    result = self.ping_host(host)
                    monitoring_data[host]['checks'] += 1
                    
                    if result['status'] == 'alive':
                        # Update average response time
                        current_avg = monitoring_data[host]['avg_response_time']
                        new_response = result['response_time']
                        monitoring_data[host]['avg_response_time'] = (
                            (current_avg * (monitoring_data[host]['checks'] - 1) + new_response) 
                            / monitoring_data[host]['checks']
                        )
                        
                        print(f"{host} - {result['response_time']}ms")
                    else:
                        monitoring_data[host]['failures'] += 1
                        print(f"{host} - FAILED")
                        
                        # Alert if threshold exceeded
                        if monitoring_data[host]['failures'] >= self.config['monitoring']['alert_threshold']:
                            self.logger.warning(f"ALERT: {host} has failed {monitoring_data[host]['failures']} times")
                
                time.sleep(self.config['monitoring']['interval'])
                
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        
        # Generate monitoring report
        self.generate_monitoring_report(monitoring_data)
    
    def generate_monitoring_report(self, monitoring_data: Dict):
        """Generate a monitoring report."""
        print(f"\\n{'='*60}")
        print("NETWORK MONITORING REPORT")
        print(f"{'='*60}")
        
        for host, data in monitoring_data.items():
            uptime_percentage = ((data['checks'] - data['failures']) / data['checks'] * 100) if data['checks'] > 0 else 0
            
            print(f"Host: {host}")
            print(f"  Checks: {data['checks']}")
            print(f"  Failures: {data['failures']}")
            print(f"  Uptime: {uptime_percentage:.2f}%")
            print(f"  Avg Response Time: {data['avg_response_time']:.2f}ms")
            print()
    
    def comprehensive_scan(self, target: str) -> Dict:
        """
        Perform a comprehensive scan of a target (host or network).
        
        Args:
            target (str): IP address, hostname, or network range
            
        Returns:
            Dict: Comprehensive scan results
        """
        self.logger.info(f"Starting comprehensive scan of {target}")
        
        scan_results = {
            'target': target,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'hosts': [],
            'summary': {}
        }
        
        try:
            # Determine if target is a network range or single host
            if '/' in target:
                # Network range
                alive_hosts = self.scan_network(target)
                scan_results['hosts'] = alive_hosts
                
                # Scan ports on alive hosts
                for host_info in alive_hosts:
                    host = host_info['host']
                    print(f"\\n🔍 Scanning ports on {host}...")
                    
                    # TCP port scan
                    tcp_ports = self.scan_ports(host, self.config['ports']['common_tcp'])
                    host_info['tcp_ports'] = tcp_ports
                    
                    # OS detection
                    os_info = self.detect_os(host)
                    host_info['os_info'] = os_info
                    
                    # Web service check
                    web_services = []
                    for port_info in tcp_ports:
                        if port_info['port'] in [80, 443, 8080, 8443]:
                            protocol = 'https' if port_info['port'] in [443, 8443] else 'http'
                            url = f"{protocol}://{host}:{port_info['port']}"
                            web_result = self.check_web_service(url)
                            web_services.append(web_result)
                    
                    host_info['web_services'] = web_services
            else:
                # Single host
                host_info = self.ping_host(target)
                if host_info['status'] == 'alive':
                    print(f"\\n🔍 Scanning ports on {target}...")
                    
                    # TCP port scan
                    tcp_ports = self.scan_ports(target, self.config['ports']['common_tcp'])
                    host_info['tcp_ports'] = tcp_ports
                    
                    # OS detection
                    os_info = self.detect_os(target)
                    host_info['os_info'] = os_info
                    
                    # Web service check
                    web_services = []
                    for port_info in tcp_ports:
                        if port_info['port'] in [80, 443, 8080, 8443]:
                            protocol = 'https' if port_info['port'] in [443, 8443] else 'http'
                            url = f"{protocol}://{target}:{port_info['port']}"
                            web_result = self.check_web_service(url)
                            web_services.append(web_result)
                    
                    host_info['web_services'] = web_services
                
                scan_results['hosts'] = [host_info] if host_info['status'] == 'alive' else []
        
        except Exception as e:
            self.logger.error(f"Error during comprehensive scan: {e}")
        
        # Generate summary
        total_hosts = len(scan_results['hosts'])
        total_open_ports = sum(len(host.get('tcp_ports', [])) for host in scan_results['hosts'])
        
        scan_results['summary'] = {
            'total_hosts_found': total_hosts,
            'total_open_ports': total_open_ports,
            'scan_duration': 'completed',
            'most_common_services': self._get_common_services(scan_results['hosts'])
        }
        
        return scan_results
    
    def _get_common_services(self, hosts: List[Dict]) -> List[str]:
        """Get most common services found during scanning."""
        service_count = {}
        
        for host in hosts:
            for port_info in host.get('tcp_ports', []):
                service = port_info.get('service', 'unknown')
                service_count[service] = service_count.get(service, 0) + 1
        
        # Return top 5 most common services
        return sorted(service_count.items(), key=lambda x: x[1], reverse=True)[:5]
    
    def save_results(self, results: Dict, filename: str = None):
        """Save scan results to JSON file."""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"network_scan_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"Results saved to {filename}")
            return filename
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            return None


def main():
    """Main function with command line argument parsing."""
    parser = argparse.ArgumentParser(
        description="Network Scanner & Monitoring Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_scanner.py --scan 192.168.1.0/24
  python network_scanner.py --host 192.168.1.1 --ports 80,443,22
  python network_scanner.py --monitor 192.168.1.1,192.168.1.2
  python network_scanner.py --comprehensive 192.168.1.0/24
        """
    )
    
    parser.add_argument(
        '-c', '--config',
        default='network_config.yaml',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--scan',
        help='Scan network range (e.g., 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '--host',
        help='Target host for port scanning'
    )
    
    parser.add_argument(
        '--ports',
        help='Comma-separated list of ports to scan'
    )
    
    parser.add_argument(
        '--monitor',
        help='Comma-separated list of hosts to monitor'
    )
    
    parser.add_argument(
        '--comprehensive',
        help='Perform comprehensive scan (network discovery + port scan + service detection)'
    )
    
    parser.add_argument(
        '--output',
        help='Output file for results (JSON format)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Network Scanner v1.0.0'
    )
    
    args = parser.parse_args()
    
    try:
        scanner = NetworkScanner(args.config)
        
        if args.scan:
            print(f" Scanning network: {args.scan}")
            results = scanner.scan_network(args.scan)
            print(f"\\nFound {len(results)} active hosts")
            
            if args.output:
                scanner.save_results({'scan_type': 'network', 'results': results}, args.output)
        
        elif args.host:
            if args.ports:
                ports = [int(p.strip()) for p in args.ports.split(',')]
            else:
                ports = scanner.config['ports']['common_tcp']
            
            print(f" Scanning ports on {args.host}")
            results = scanner.scan_ports(args.host, ports)
            print(f"\\n Found {len(results)} open ports")
            
            if args.output:
                scanner.save_results({'scan_type': 'port', 'host': args.host, 'results': results}, args.output)
        
        elif args.monitor:
            hosts = [h.strip() for h in args.monitor.split(',')]
            print(f"Starting network monitoring for {len(hosts)} hosts")
            scanner.monitor_network(hosts)
        
        elif args.comprehensive:
            print(f"🔬 Starting comprehensive scan of {args.comprehensive}")
            results = scanner.comprehensive_scan(args.comprehensive)
            
            # Display summary
            print(f"\\n SCAN SUMMARY")
            print(f"Target: {results['target']}")
            print(f"Hosts found: {results['summary']['total_hosts_found']}")
            print(f"Open ports found: {results['summary']['total_open_ports']}")
            print(f"Common services: {results['summary']['most_common_services']}")
            
            if args.output:
                filename = scanner.save_results(results, args.output)
                print(f"\\n Results saved to: {filename}")
        
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\\n Scan interrupted by user")
    except Exception as e:
        print(f" Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())


print("=== Network Scanner & Monitoring Tool - Complete Python Code ===")
print("File: network_scanner.py")
print("=" * 70)
print(network_scanner_code)