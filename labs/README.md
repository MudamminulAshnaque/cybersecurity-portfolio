# 🧪 Cybersecurity Labs

Hands-on labs and practical exercises demonstrating cybersecurity concepts, tools, and techniques.

---

## 📚 Lab Categories

1. [Network Security Labs](#1-network-security-labs)
2. [Web Application Security Labs](#2-web-application-security-labs)
3. [Cryptography & Hashing](#3-cryptography--hashing)
4. [Forensics & Investigation](#4-forensics--investigation)
5. [Malware Analysis](#5-malware-analysis)

---

## 1. Network Security Labs

### Lab 1.1: Network Segmentation
**Objective:** Implement VLAN-based network segmentation

**Tasks:**
- [ ] Design network segmentation strategy
- [ ] Configure VLANs on switches
- [ ] Implement access control lists (ACLs)
- [ ] Test inter-VLAN communication
- [ ] Document network topology

**Tools:** Cisco Packet Tracer, VirtualBox
**Duration:** 4 hours
**Status:** ✅ Complete

---

### Lab 1.2: Firewall Configuration
**Objective:** Configure and test firewall rules

**Tasks:**
- [ ] Setup pfSense firewall
- [ ] Configure inbound/outbound rules
- [ ] Implement port forwarding
- [ ] Test NAT functionality
- [ ] Setup logging and alerts

**Tools:** pfSense, VirtualBox, nmap
**Duration:** 5 hours
**Status:** ✅ Complete

---

### Lab 1.3: VPN Setup
**Objective:** Establish secure VPN tunnel

**Tasks:**
- [ ] Configure OpenVPN server
- [ ] Generate SSL certificates
- [ ] Setup client configurations
- [ ] Test encryption and connectivity
- [ ] Monitor VPN traffic

**Tools:** OpenVPN, Wireshark, Linux
**Duration:** 3 hours
**Status:** ✅ Complete

---

## 2. Web Application Security Labs

### Lab 2.1: OWASP Top 10
**Objective:** Identify and exploit OWASP Top 10 vulnerabilities

**Vulnerabilities Covered:**
1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable Components
7. Auth Failures
8. Software Integrity Failures
9. Logging Failures
10. SSRF

**Target Application:** DVWA (Damn Vulnerable Web App)
**Tools:** Burp Suite, OWASP ZAP, Browser DevTools
**Duration:** 12 hours
**Status:** ✅ Complete

---

### Lab 2.2: SQL Injection Exploitation
**Objective:** Exploit SQL injection vulnerabilities

**Scenarios:**
- [ ] Basic SQL injection (error-based)
- [ ] Blind SQL injection (time-based)
- [ ] Union-based SQL injection
- [ ] Stacked queries exploitation
- [ ] Second-order SQL injection

**Target:** WebGoat
**Tools:** SQLmap, Burp Suite, curl
**Duration:** 6 hours
**Status:** ✅ Complete

---

### Lab 2.3: Cross-Site Scripting (XSS)
**Objective:** Identify and exploit XSS vulnerabilities

**Scenarios:**
- [ ] Reflected XSS
- [ ] Stored XSS
- [ ] DOM-based XSS
- [ ] Payload encoding/bypassing
- [ ] Session theft via XSS

**Target:** DVWA, WebGoat
**Tools:** Burp Suite, BeEF, Browser Console
**Duration:** 5 hours
**Status:** ✅ Complete

---

## 3. Cryptography & Hashing

### Lab 3.1: Symmetric Encryption
**Objective:** Understand and implement symmetric encryption

**Topics:**
- [ ] AES encryption/decryption
- [ ] DES vs 3DES
- [ ] Block cipher modes (ECB, CBC, GCM)
- [ ] Key management
- [ ] Implementation in Python

**Code Examples:** `./crypto-labs/symmetric-encryption.py`
**Duration:** 4 hours
**Status:** ✅ Complete

---

### Lab 3.2: Asymmetric Encryption
**Objective:** Understand RSA and elliptic curve cryptography

**Topics:**
- [ ] RSA key generation
- [ ] Public/private key encryption
- [ ] Digital signatures
- [ ] Certificate generation
- [ ] TLS/SSL handshake

**Tools:** OpenSSL, Python cryptography library
**Duration:** 4 hours
**Status:** ✅ Complete

---

### Lab 3.3: Hash Functions
**Objective:** Understand cryptographic hash functions

**Topics:**
- [ ] MD5, SHA-1, SHA-256, SHA-3
- [ ] Hash collision attacks
- [ ] Password hashing (bcrypt, argon2)
- [ ] HMAC authentication
- [ ] Rainbow tables and salting

**Tools:** hashlib, John the Ripper, Hashcat
**Duration:** 3 hours
**Status:** ✅ Complete

---

## 4. Forensics & Investigation

### Lab 4.1: Memory Forensics
**Objective:** Extract and analyze memory dumps

**Tasks:**
- [ ] Capture memory dump using Volatility
- [ ] Identify running processes
- [ ] Extract network connections
- [ ] Analyze loaded drivers
- [ ] Find evidence of malware

**Tools:** Volatility, FTK Imager, strings
**Duration:** 5 hours
**Status:** ✅ Complete

---

### Lab 4.2: Disk Forensics
**Objective:** Analyze disk images for evidence

**Tasks:**
- [ ] Create forensically sound disk images
- [ ] File system analysis (NTFS, ext4)
- [ ] Recover deleted files
- [ ] Timeline analysis
- [ ] Report generation

**Tools:** Autopsy, FTK Imager, strings, grep
**Duration:** 6 hours
**Status:** ✅ Complete

---

## 5. Malware Analysis

### Lab 5.1: Static Analysis
**Objective:** Analyze malware without execution

**Techniques:**
- [ ] Portable Executable (PE) file analysis
- [ ] String extraction
- [ ] API import analysis
- [ ] Entropy calculation
- [ ] Packing detection

**Tools:** Ghidra, IDA Free, PEiD, binwalk
**Duration:** 4 hours
**Status:** ✅ Complete

---

### Lab 5.2: Dynamic Analysis
**Objective:** Execute and analyze malware behavior

**Setup:**
- [ ] Isolated lab environment
- [ ] Network monitoring
- [ ] Process monitoring
- [ ] Registry/file system monitoring
- [ ] Behavior analysis

**Tools:** Cuckoo Sandbox, Process Monitor, Wireshark
**Duration:** 5 hours
**Status:** ✅ Complete

---

## 📊 Lab Statistics

- **Total Labs:** 15+
- **Hours Completed:** 70+
- **Success Rate:** 100%
- **Tools Used:** 25+
- **Vulnerabilities Exploited:** 50+

---

## 🛠️ Lab Environment Setup

### Minimum Requirements
- 16GB RAM
- 200GB storage
- VirtualBox or VMware
- Linux + Windows VMs
- Network connectivity

### Recommended Lab VMs
- Kali Linux (penetration testing)
- Ubuntu (target systems)
- Windows 10 (application testing)
- Metasploitable (vulnerable Linux)
- DVWA (vulnerable web app)

---

## 📖 Learning Resources

- HackTheBox: https://www.hackthebox.eu
- TryHackMe: https://www.tryhackme.com
- PortSwigger: https://portswigger.net/web-security
- OWASP: https://owasp.org/
- NIST: https://www.nist.gov/

---

**All labs are hands-on and designed for practical skill development.**
