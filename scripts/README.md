# 🐍 Security Scripts & Automation Tools

Collection of Python and Bash scripts for network security, vulnerability assessment, and incident response automation.

---

## 📂 Script Categories

1. [Network Scanning Tools](#1-network-scanning-tools)
2. [Vulnerability Assessment](#2-vulnerability-assessment)
3. [Log Analysis & SIEM](#3-log-analysis--siem)
4. [Incident Response](#4-incident-response)
5. [Utility Scripts](#5-utility-scripts)

---

## 1. Network Scanning Tools

### `port_scanner.py`
**Purpose:** Advanced multi-threaded network port scanner

**Features:**
- Fast multi-threaded scanning
- Service detection
- Version detection
- Export to JSON/CSV
- Progress bar

**Usage:**
```bash
python3 port_scanner.py -t 192.168.1.100 -p 1-1000 --threads 50
```

**Requires:** `pip install nmap-python`

---

### `network_mapper.py`
**Purpose:** Discover and map network topology

**Features:**
- ARP scanning for active hosts
- Subnet discovery
- Device OS detection
- Network visualization
- Export topology diagram

**Usage:**
```bash
python3 network_mapper.py -s 192.168.1.0/24
```

---

### `packet_analyzer.py`
**Purpose:** Analyze PCAP files and live traffic

**Features:**
- Protocol analysis
- Packet filtering
- Statistics generation
- Threat detection
- Report generation

**Usage:**
```bash
python3 packet_analyzer.py -f capture.pcap --filter "tcp.port==80"
```

---

## 2. Vulnerability Assessment

### `vuln_scanner.py`
**Purpose:** Custom vulnerability scanner integrating multiple sources

**Features:**
- Nmap integration
- CVE database lookup
- Severity scoring
- Automated reporting
- Remediation recommendations

**Usage:**
```bash
python3 vuln_scanner.py -t 192.168.1.100 -o report.html
```

---

### `cve_lookup.py`
**Purpose:** Query CVE databases for vulnerability information

**Features:**
- CVSS scoring
- Exploit availability
- EPSS (Exploit Prediction Scoring System)
- Affected versions
- Remediation guidance

**Usage:**
```bash
python3 cve_lookup.py --cve CVE-2021-44228
```

---

### `config_auditor.sh`
**Purpose:** Automated configuration compliance checking

**Features:**
- CIS Benchmarks compliance
- Security best practices validation
- Permission checking
- Service hardening verification

**Usage:**
```bash
bash config_auditor.sh -s linux -b "CIS Ubuntu 20.04"
```

---

## 3. Log Analysis & SIEM

### `log_analyzer.py`
**Purpose:** Parse, analyze, and correlate security logs

**Features:**
- Multi-format log parsing (syslog, JSON, CSV)
- Event correlation
- Anomaly detection
- Alert generation
- Visualization

**Supported Log Types:**
- Apache/Nginx access/error logs
- Windows event logs
- Firewall logs
- IDS/IPS alerts
- Authentication logs

**Usage:**
```bash
python3 log_analyzer.py -f /var/log/auth.log --analysis brute-force
```

---

### `threat_hunter.py`
**Purpose:** Pattern detection and threat hunting in network logs

**Features:**
- Behavioral analysis
- Anomaly detection using ML
- Pattern matching
- Threat scoring
- Timeline reconstruction

**Usage:**
```bash
python3 threat_hunter.py --hunt lateral-movement --days 7
```

---

### `firewall_auditor.sh`
**Purpose:** Analyze and audit firewall rules

**Features:**
- Rule effectiveness analysis
- Unused rule detection
- Conflicting rule identification
- Security gap analysis
- Report generation

**Usage:**
```bash
bash firewall_auditor.sh -c /etc/ufw/rules.txt
```

---

## 4. Incident Response

### `incident_responder.py`
**Purpose:** Automated incident response coordination

**Features:**
- Alert triage and classification
- Playbook execution
- Evidence collection
- Notification system
- Incident documentation

**Usage:**
```bash
python3 incident_responder.py --alert-id INC-2024-001
```

---

### `evidence_collector.sh`
**Purpose:** Automated forensic evidence collection

**Features:**
- Memory dump capture
- Network connection logging
- Process enumeration
- File system snapshot
- Timeline creation

**Usage:**
```bash
sudo bash evidence_collector.sh --output /mnt/evidence/
```

---

### `threat_intelligence.py`
**Purpose:** Gather and enrich threat intelligence

**Features:**
- IP/domain reputation lookup
- Malware analysis queries
- OSINT automation
- Data aggregation
- Report generation

**Usage:**
```bash
python3 threat_intelligence.py --ip 192.0.2.1 --enrich
```

---

## 5. Utility Scripts

### `password_manager.py`
**Purpose:** Secure password generation and storage

**Features:**
- Cryptographically secure generation
- Complexity requirements
- Encrypted storage
- Password strength analysis

**Usage:**
```bash
python3 password_manager.py --generate --length 32 --complexity high
```

---

### `ssl_certificate_checker.sh`
**Purpose:** Monitor and audit SSL/TLS certificates

**Features:**
- Certificate expiration tracking
- Chain validation
- Key strength verification
- Vulnerability checking
- Alert generation

**Usage:**
```bash
bash ssl_certificate_checker.sh --domain example.com
```

---

### `compliance_reporter.py`
**Purpose:** Generate compliance reports

**Features:**
- Framework reporting (NIST, CIS, OWASP)
- Control mapping
- Gap analysis
- Remediation tracking
- Executive summaries

**Usage:**
```bash
python3 compliance_reporter.py --framework NIST-CSF --format PDF
```

---

## 🛠️ Installation & Setup

### Prerequisites
```bash
# Python 3.8+
python3 --version

# Install dependencies
pip install -r requirements.txt

# For network tools, install additional packages
sudo apt-get install nmap wireshark tcpdump
```

### Creating Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📋 Dependencies

See `requirements.txt` for complete list:

```
requests>=2.28.0
nmap-python>=0.0.1
scapy>=2.4.5
pandas>=1.5.0
numpy>=1.23.0
matplotlib>=3.6.0
beautifulsoup4>=4.11.0
pycryptodome>=3.15.0
violin>=0.1.0
jinja2>=3.1.0
pyyaml>=6.0
```

---

## 🔐 Security Considerations

⚠️ **Important:** These tools are designed for:
- Authorized security testing
- Internal vulnerability assessments
- Educational purposes
- Authorized penetration testing

**Always obtain written authorization before conducting any security assessments.**

---

## 📊 Script Statistics

- **Total Scripts:** 20+
- **Lines of Code:** 3,000+
- **Languages:** Python 3, Bash
- **Features:** 50+
- **Use Cases:** Enterprise security

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Test scripts thoroughly
2. Document code clearly
3. Follow PEP 8 standards
4. Add error handling
5. Update README with usage examples

---

## 📞 Support

For issues or questions:
- Check documentation in script comments
- Review usage examples
- Open an issue with details

---

**Remember:** Use these tools responsibly and ethically. 🔐
