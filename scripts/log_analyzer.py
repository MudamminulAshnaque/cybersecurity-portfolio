#!/usr/bin/env python3
"""
Security Log Analysis Tool
Author: Mudamminul Ashnaque
Description: Parse, analyze, and correlate security logs from multiple sources
"""

import json
import re
import argparse
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.logs = []
        self.anomalies = []
        
    def parse_logs(self):
        """Parse log file and extract structured data"""
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    # Skip empty lines and comments
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Try to parse as JSON first
                    try:
                        log_entry = json.loads(line)
                    except:
                        # Fall back to syslog format parsing
                        log_entry = self.parse_syslog_line(line)
                    
                    if log_entry:
                        self.logs.append(log_entry)
            
            print(f"[+] Parsed {len(self.logs)} log entries")
        except FileNotFoundError:
            print(f"[!] Log file not found: {self.log_file}")
    
    def parse_syslog_line(self, line):
        """Parse traditional syslog format"""
        # Example: Dec 22 12:34:56 hostname process[pid]: message
        pattern = r'(\w+\s+\d+\s+[\d:]+)\s+([\w.-]+)\s+([\w.-]+)\[(\d+)\]:\s+(.*)'
        match = re.match(pattern, line)
        
        if match:
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'process': match.group(3),
                'pid': match.group(4),
                'message': match.group(5),
                'raw': line
            }
        return None
    
    def detect_brute_force(self, threshold=5):
        """Detect brute force attack attempts"""
        failed_attempts = defaultdict(int)
        
        for log in self.logs:
            if 'Failed password' in log.get('message', '') or 'authentication failure' in log.get('message', ''):
                # Extract source IP
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', log.get('raw', ''))
                if ip_match:
                    ip = ip_match.group()
                    failed_attempts[ip] += 1
        
        # Report suspicious IPs
        suspicious = {ip: count for ip, count in failed_attempts.items() if count >= threshold}
        
        for ip, count in suspicious.items():
            self.anomalies.append({
                'type': 'brute_force',
                'source': ip,
                'count': count,
                'severity': 'HIGH' if count > 10 else 'MEDIUM'
            })
        
        return suspicious
    
    def detect_port_scanning(self):
        """Detect potential port scanning activity"""
        connection_attempts = defaultdict(lambda: defaultdict(int))
        
        for log in self.logs:
            if 'Connection refused' in log.get('message', ''):
                # Extract source and destination IPs
                ips = re.findall(r'\d+\.\d+\.\d+\.\d+', log.get('raw', ''))
                if len(ips) >= 2:
                    src, dst = ips[0], ips[1]
                    connection_attempts[src][dst] += 1
        
        # Alert on suspicious scanning patterns
        suspicious_scanners = {}
        for src, destinations in connection_attempts.items():
            if len(destinations) > 50:  # Many different destinations
                suspicious_scanners[src] = len(destinations)
                self.anomalies.append({
                    'type': 'port_scan',
                    'source': src,
                    'destinations': len(destinations),
                    'severity': 'HIGH'
                })
        
        return suspicious_scanners
    
    def detect_privilege_escalation(self):
        """Detect privilege escalation attempts"""
        escalation_keywords = ['sudo:', 'su -', 'privilege', 'elevated', 'permission denied']
        suspicious_users = defaultdict(int)
        
        for log in self.logs:
            message = log.get('message', '').lower()
            if any(keyword.lower() in message for keyword in escalation_keywords):
                # Extract username
                user_match = re.search(r'user=([\w.-]+)', message)
                if user_match:
                    user = user_match.group(1)
                    suspicious_users[user] += 1
        
        for user, count in suspicious_users.items():
            if count > 3:
                self.anomalies.append({
                    'type': 'privilege_escalation',
                    'user': user,
                    'attempts': count,
                    'severity': 'HIGH'
                })
        
        return suspicious_users
    
    def generate_statistics(self):
        """Generate log statistics"""
        stats = {
            'total_entries': len(self.logs),
            'unique_hosts': len(set(log.get('hostname', 'unknown') for log in self.logs)),
            'unique_processes': len(set(log.get('process', 'unknown') for log in self.logs)),
            'anomalies_detected': len(self.anomalies),
            'timestamp_range': {
                'first': self.logs[0].get('timestamp') if self.logs else None,
                'last': self.logs[-1].get('timestamp') if self.logs else None
            }
        }
        return stats
    
    def generate_report(self, output_file=None):
        """Generate comprehensive analysis report"""
        # Run all analysis
        brute_force = self.detect_brute_force()
        port_scans = self.detect_port_scanning()
        escalations = self.detect_privilege_escalation()
        stats = self.generate_statistics()
        
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'log_file': str(self.log_file),
            'statistics': stats,
            'findings': {
                'brute_force_attempts': brute_force,
                'port_scans': port_scans,
                'privilege_escalations': escalations
            },
            'anomalies': self.anomalies,
            'severity_summary': {
                'critical': len([a for a in self.anomalies if a.get('severity') == 'CRITICAL']),
                'high': len([a for a in self.anomalies if a.get('severity') == 'HIGH']),
                'medium': len([a for a in self.anomalies if a.get('severity') == 'MEDIUM']),
                'low': len([a for a in self.anomalies if a.get('severity') == 'LOW'])
            }
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {output_file}")
        
        return report
    
    def print_summary(self):
        """Print summary of analysis"""
        stats = self.generate_statistics()
        print("\n" + "="*50)
        print("LOG ANALYSIS SUMMARY")
        print("="*50)
        print(f"Total log entries: {stats['total_entries']}")
        print(f"Unique hosts: {stats['unique_hosts']}")
        print(f"Unique processes: {stats['unique_processes']}")
        print(f"Anomalies detected: {stats['anomalies_detected']}")
        print("="*50 + "\n")

def main():
    parser = argparse.ArgumentParser(description='Security Log Analysis Tool')
    parser.add_argument('log_file', help='Path to log file')
    parser.add_argument('--analysis', choices=['brute-force', 'port-scan', 'privilege-escalation', 'all'],
                        default='all', help='Type of analysis to perform')
    parser.add_argument('-o', '--output', help='Output file for report (JSON)')
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer(args.log_file)
    analyzer.parse_logs()
    
    if args.analysis == 'all':
        report = analyzer.generate_report(args.output)
        analyzer.print_summary()
    else:
        analyzer.parse_logs()
        if args.analysis == 'brute-force':
            print("[*] Analyzing for brute force attacks...")
            results = analyzer.detect_brute_force()
        elif args.analysis == 'port-scan':
            print("[*] Analyzing for port scanning...")
            results = analyzer.detect_port_scanning()
        elif args.analysis == 'privilege-escalation':
            print("[*] Analyzing for privilege escalation...")
            results = analyzer.detect_privilege_escalation()
        
        print(json.dumps(results, indent=2))

if __name__ == '__main__':
    main()
