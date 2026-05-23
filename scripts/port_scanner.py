#!/usr/bin/env python3
"""
Advanced Multi-threaded Port Scanner
Author: Mudamminul Ashnaque
Description: Fast TCP port scanner with service detection and export capabilities
"""

import socket
import argparse
import threading
import json
import csv
from datetime import datetime
from queue import Queue
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

class PortScanner:
    def __init__(self, host, ports, threads=50, timeout=2):
        self.host = host
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.queue = Queue()
        self.lock = threading.Lock()
        
    def get_service_name(self, port):
        """Get service name for a given port"""
        try:
            return socket.getservbyport(port)
        except:
            return "Unknown"
    
    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, port))
            sock.close()
            
            if result == 0:
                service = self.get_service_name(port)
                with self.lock:
                    self.open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'open',
                        'timestamp': datetime.now().isoformat()
                    })
                    print(f"{Fore.GREEN}[+] Port {port} is open - {service}{Style.RESET_ALL}")
        except socket.gaierror:
            print(f"{Fore.RED}[!] Hostname {self.host} could not be resolved{Style.RESET_ALL}")
            return
        except socket.error:
            return
    
    def worker(self):
        """Worker thread for scanning ports"""
        while True:
            port = self.queue.get()
            if port is None:
                break
            self.scan_port(port)
            self.queue.task_done()
    
    def run(self):
        """Start the port scanning process"""
        print(f"{Fore.CYAN}[*] Starting port scan on {self.host}{Style.RESET_ALL}")
        print(f"[*] Scanning ports {self.ports} with {self.threads} threads\n")
        
        # Fill queue with ports
        port_list = self.parse_ports()
        for port in port_list:
            self.queue.put(port)
        
        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
        
        # Wait for queue to be processed
        self.queue.join()
        
        # Stop workers
        for _ in range(self.threads):
            self.queue.put(None)
        
        for t in threads:
            t.join()
        
        print(f"\n{Fore.CYAN}[*] Scan complete!{Style.RESET_ALL}")
        print(f"[*] Found {len(self.open_ports)} open ports\n")
        
        return self.open_ports
    
    def parse_ports(self):
        """Parse port range specification"""
        ports = []
        if '-' in str(self.ports):
            start, end = map(int, self.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in self.ports.split(',')]
        return ports
    
    def export_json(self, filename):
        """Export results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.open_ports, f, indent=2)
        print(f"{Fore.GREEN}[+] Results exported to {filename}{Style.RESET_ALL}")
    
    def export_csv(self, filename):
        """Export results to CSV"""
        if not self.open_ports:
            print(f"{Fore.YELLOW}[!] No ports to export{Style.RESET_ALL}")
            return
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['port', 'service', 'status', 'timestamp'])
            writer.writeheader()
            writer.writerows(self.open_ports)
        print(f"{Fore.GREEN}[+] Results exported to {filename}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Multi-threaded Port Scanner'
    )
    parser.add_argument('-t', '--target', required=True, help='Target host or IP')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range (e.g., 1-1000 or 80,443,8080)')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=2, help='Connection timeout in seconds')
    parser.add_argument('-o', '--output', help='Output file (json or csv)')
    
    args = parser.parse_args()
    
    scanner = PortScanner(args.target, args.ports, args.threads, args.timeout)
    results = scanner.run()
    
    # Export results if requested
    if args.output:
        if args.output.endswith('.json'):
            scanner.export_json(args.output)
        elif args.output.endswith('.csv'):
            scanner.export_csv(args.output)

if __name__ == '__main__':
    main()
