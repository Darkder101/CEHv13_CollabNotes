# CEH v13 OSI Model - Complete Exam-Focused Notes

## Table of Contents
1. [OSI Model Overview](#osi-model-overview)
2. [Layer-by-Layer Analysis](#layer-by-layer-analysis)
3. [Security Threats by Layer](#security-threats-by-layer)
4. [Tools and Techniques by Layer](#tools-and-techniques-by-layer)
5. [Attack Scenarios by Layer](#attack-scenarios-by-layer)
6. [Common Exam Question Types](#common-exam-question-types)
7. [Protocol Analysis](#protocol-analysis)
8. [Practical Lab Scenarios](#practical-lab-scenarios)
9. [Quick Reference Tables](#quick-reference-tables)
10. [Exam Strategy & Tips](#exam-strategy--tips)

---

## OSI Model Overview

### The 7 Layers (Bottom to Top)
```
Layer 7 - Application Layer    (Closest to User)
Layer 6 - Presentation Layer   
Layer 5 - Session Layer        
Layer 4 - Transport Layer      
Layer 3 - Network Layer        
Layer 2 - Data Link Layer      
Layer 1 - Physical Layer       (Closest to Hardware)
```

### Memory Aids
```
Physical (1): "Please" - Physical cables and signals
Data Link (2): "Do" - Data frames and MAC addresses  
Network (3): "Not" - Network routing and IP addresses
Transport (4): "Throw" - TCP/UDP and port numbers
Session (5): "Sausage" - Sessions and NetBIOS
Presentation (6): "Pizza" - Pretty data (encryption/formatting)
Application (7): "Away" - Applications and user interfaces
```

### Key Exam Concepts
- **Data Flow**: How data travels through layers
- **Encapsulation**: Adding headers at each layer
- **De-encapsulation**: Removing headers at destination
- **PDU (Protocol Data Units)**: Data format at each layer

### PDU Names by Layer
| Layer | PDU Name | Key Components |
|-------|----------|----------------|
| 7-Application | Data | User data |
| 6-Presentation | Data | Encrypted/Compressed data |
| 5-Session | Data | Session management |
| 4-Transport | Segment/Datagram | Port numbers |
| 3-Network | Packet | IP addresses |
| 2-Data Link | Frame | MAC addresses |
| 1-Physical | Bits | Electrical signals |

---

## Layer-by-Layer Analysis

### Layer 1 - Physical Layer

#### **What It Does**
- Transmits raw bits over physical medium
- Defines electrical, mechanical, procedural specifications
- Handles physical connections and signaling

#### **Key Components**
- Cables (Ethernet, Fiber optic, Coaxial)
- Hubs, Repeaters, Network adapters
- Wireless radio frequencies
- Voltage levels and timing

#### **Security Concerns**
- **Physical access attacks**
- **Cable tapping/wiretapping**
- **Electromagnetic interference**
- **Signal jamming**

#### **Common Exam Scenarios**
```
Scenario: "An attacker physically accesses the server room and connects 
a device to intercept network traffic. Which layer is primarily compromised?"
Answer: Layer 1 (Physical Layer)
```

#### **Tools for Layer 1**
- **Cable testers**: Verify physical connectivity
- **Protocol analyzers**: Hardware-based packet capture
- **RF analyzers**: Wireless signal analysis
- **Physical security tools**: Locks, cameras, sensors

---

### Layer 2 - Data Link Layer

#### **What It Does**
- Provides error-free transfer between adjacent nodes
- Handles MAC addressing
- Frame formatting and error detection
- Flow control between directly connected devices

#### **Key Protocols**
- **Ethernet (IEEE 802.3)**
- **Wi-Fi (IEEE 802.11)**
- **PPP (Point-to-Point Protocol)**
- **ARP (Address Resolution Protocol)**

#### **Security Concerns**
- **ARP poisoning/spoofing**
- **MAC address spoofing**
- **Switch flooding attacks**
- **VLAN hopping**
- **STP (Spanning Tree Protocol) attacks**

#### **Common Exam Questions**
```
Q: "Which attack involves sending fake ARP responses to associate 
attacker's MAC with victim's IP address?"
A: ARP Poisoning/Spoofing (Layer 2 attack)

Q: "What tool is commonly used for ARP poisoning attacks?"
A: Ettercap, Bettercap, or arpspoof
```

#### **Tools for Layer 2**
- **Ettercap**: ARP poisoning, MITM attacks
- **Bettercap**: Modern network attacks and monitoring
- **Yersinia**: Layer 2 attack framework
- **macchanger**: MAC address spoofing
- **Wireshark**: Frame analysis

#### **Attack Examples**
```bash
# ARP Poisoning with Ettercap
ettercap -T -i eth0 -M arp:remote /192.168.1.1/ /192.168.1.100/

# MAC Address Spoofing
macchanger -m 00:11:22:33:44:55 eth0
```

---

### Layer 3 - Network Layer

#### **What It Does**
- Routing packets between different networks
- Logical addressing (IP addresses)
- Path determination
- Fragmentation and reassembly

#### **Key Protocols**
- **IPv4/IPv6**: Internet Protocol
- **ICMP**: Internet Control Message Protocol
- **OSPF**: Open Shortest Path First
- **BGP**: Border Gateway Protocol
- **IPSec**: IP Security

#### **Security Concerns**
- **IP spoofing**
- **ICMP attacks** (Ping of death, Smurf attack)
- **Routing table poisoning**
- **IP fragmentation attacks**
- **DoS/DDoS attacks**

#### **High-Frequency Exam Topics**
```
Scenario: "An attacker sends ICMP packets with spoofed source addresses 
to a broadcast address, causing all hosts to reply to the victim. 
What is this attack called?"
Answer: Smurf Attack (Layer 3 - ICMP flood)

Q: "Which tool is used to perform IP spoofing attacks?"
A: hping3, Scapy, or Nmap (with spoofing options)
```

#### **Tools for Layer 3**
- **hping3**: Crafting custom packets, IP spoofing
- **Scapy**: Python-based packet manipulation
- **Nmap**: Network discovery and security scanning
- **ping/traceroute**: Network diagnostics
- **route**: Routing table manipulation

#### **Attack Commands**
```bash
# IP Spoofing with hping3
hping3 -a 192.168.1.50 -S -p 80 192.168.1.100

# ICMP Flood
hping3 --icmp -i u1 192.168.1.100

# Traceroute with spoofed source
hping3 -S -a 192.168.1.50 -t 1 192.168.1.1
```

---

### Layer 4 - Transport Layer

#### **What It Does**
- End-to-end communication
- Port addressing
- Segmentation and reassembly
- Flow control and error recovery

#### **Key Protocols**
- **TCP (Transmission Control Protocol)**: Reliable, connection-oriented
- **UDP (User Datagram Protocol)**: Unreliable, connectionless
- **SCTP (Stream Control Transmission Protocol)**

#### **Security Concerns**
- **Port scanning**
- **TCP hijacking**
- **SYN flood attacks**
- **UDP flood attacks**
- **Session hijacking**

#### **Critical Exam Knowledge**
```
TCP Three-Way Handshake:
1. SYN (Client → Server)
2. SYN-ACK (Server → Client)
3. ACK (Client → Server)

Common Attack: SYN Flood
- Attacker sends multiple SYN packets
- Never completes handshake
- Exhausts server resources
```

#### **Port Scanning Types (Layer 4 Focus)**
- **TCP Connect Scan**: Complete three-way handshake
- **TCP SYN Scan**: Half-open scanning
- **TCP FIN Scan**: Sends FIN packets
- **UDP Scan**: Targets UDP services

#### **Tools for Layer 4**
- **Nmap**: Port scanning and service detection
- **hping3**: Custom TCP/UDP packet crafting
- **Netcat (nc)**: Network connections and port scanning
- **masscan**: High-speed port scanner
- **Zmap**: Internet-wide scanning

#### **Exam-Focused Commands**
```bash
# TCP SYN Scan (Stealth scan)
nmap -sS 192.168.1.100

# UDP Scan
nmap -sU 192.168.1.100

# TCP Connect Scan
nmap -sT 192.168.1.100

# SYN Flood Attack
hping3 -S --flood -V -p 80 192.168.1.100
```

---

### Layer 5 - Session Layer

#### **What It Does**
- Establishes, manages, and terminates sessions
- Dialog control (half-duplex/full-duplex)
- Session checkpointing and recovery
- Authentication and authorization

#### **Key Protocols**
- **NetBIOS**: Network Basic Input/Output System
- **RPC**: Remote Procedure Call
- **PPTP**: Point-to-Point Tunneling Protocol
- **L2TP**: Layer 2 Tunneling Protocol
- **SOCKS**: Socket Secure protocol

#### **Security Concerns**
- **Session hijacking**
- **Session fixation**
- **NetBIOS enumeration**
- **RPC vulnerabilities**
- **Tunnel attacks**

#### **Common Exam Scenarios**
```
Q: "Which layer is responsible for establishing and managing 
communication sessions between applications?"
A: Session Layer (Layer 5)

Scenario: "An attacker enumerates NetBIOS shares on a Windows network 
to gather information about available resources. Which layer protocol 
is being targeted?"
A: Layer 5 (NetBIOS)
```

#### **Tools for Layer 5**
- **enum4linux**: NetBIOS enumeration
- **smbclient**: SMB/CIFS client
- **rpcclient**: RPC client tool
- **nbtscan**: NetBIOS name scanner
- **Burp Suite**: Session management testing

#### **Attack Examples**
```bash
# NetBIOS Enumeration
enum4linux -a 192.168.1.100
nbtscan 192.168.1.0/24

# SMB Enumeration
smbclient -L //192.168.1.100 -N

# RPC Enumeration
rpcclient -U "" -N 192.168.1.100
```

---

### Layer 6 - Presentation Layer

#### **What It Does**
- Data translation, encryption, and compression
- Character encoding (ASCII, EBCDIC, Unicode)
- Data formatting and syntax conversion
- SSL/TLS encryption

#### **Key Functions**
- **Encryption/Decryption**: SSL/TLS, IPSec
- **Compression**: ZIP, GZIP
- **Data formatting**: JPEG, GIF, MPEG
- **Character encoding**: ASCII to EBCDIC conversion

#### **Security Concerns**
- **SSL/TLS attacks**
- **Encryption vulnerabilities**
- **Data compression attacks**
- **Certificate-based attacks**

#### **High-Yield Exam Topics**
```
SSL/TLS Vulnerabilities:
- BEAST attack
- POODLE attack  
- Heartbleed vulnerability
- Weak cipher suites
- Certificate validation issues

Q: "Which layer handles SSL/TLS encryption?"
A: Presentation Layer (Layer 6)
```

#### **Tools for Layer 6**
- **SSLscan**: SSL/TLS configuration scanner
- **sslstrip**: SSL stripping attacks
- **testssl.sh**: SSL/TLS testing script
- **OpenSSL**: SSL/TLS toolkit
- **Qualys SSL Labs**: Online SSL testing

#### **Attack Commands**
```bash
# SSL/TLS Scanning
sslscan 192.168.1.100:443
nmap --script ssl-enum-ciphers -p 443 192.168.1.100

# SSL Certificate Information
openssl s_client -connect 192.168.1.100:443

# SSL Strip Attack (requires MITM position)
sslstrip -l 8080
```

---

### Layer 7 - Application Layer

#### **What It Does**
- Interface between network and applications
- Provides network services to applications
- User authentication and privacy
- File transfers, email, web browsing

#### **Key Protocols**
- **HTTP/HTTPS**: Web traffic
- **FTP/SFTP**: File transfer
- **SMTP/POP3/IMAP**: Email protocols
- **DNS**: Domain Name System
- **SNMP**: Network management
- **Telnet/SSH**: Remote access

#### **Security Concerns**
- **Web application attacks** (XSS, SQL injection)
- **DNS attacks** (DNS spoofing, cache poisoning)
- **Email attacks** (Phishing, spam)
- **Buffer overflow attacks**
- **Protocol-specific vulnerabilities**

#### **Critical Exam Knowledge**
```
Web Application Attacks (Layer 7):
- SQL Injection
- Cross-Site Scripting (XSS)  
- Cross-Site Request Forgery (CSRF)
- Directory traversal
- Command injection

DNS Attacks:
- DNS spoofing
- DNS cache poisoning
- DNS tunneling
- DNS amplification (DDoS)
```

#### **Tools for Layer 7**
- **Burp Suite**: Web application security testing
- **OWASP ZAP**: Web application scanner
- **Nmap**: Service and version detection
- **dig/nslookup**: DNS queries
- **curl/wget**: HTTP client tools
- **sqlmap**: SQL injection testing
- **Nikto**: Web server scanner

#### **Attack Examples**
```bash
# Web Application Scanning
nikto -h http://192.168.1.100
nmap -sV -p 80,443 192.168.1.100

# DNS Enumeration
dig @192.168.1.1 example.com ANY
nslookup -type=mx example.com

# SQL Injection Testing
sqlmap -u "http://example.com/page.php?id=1" --dbs

# Directory Traversal
curl "http://example.com/page.php?file=../../../etc/passwd"
```

---

## Security Threats by Layer

### Layer 1 (Physical) Threats
| Threat | Description | Impact | Mitigation |
|--------|-------------|--------|------------|
| Cable Tapping | Physical interception | Data theft | Physical security, encryption |
| Hardware Tampering | Device modification | System compromise | Secure facilities, monitoring |
| Signal Jamming | RF interference | Service disruption | Frequency hopping, shielding |

### Layer 2 (Data Link) Threats
| Threat | Description | Tool | Detection |
|--------|-------------|------|-----------|
| ARP Spoofing | Fake ARP responses | Ettercap | ARP monitoring tools |
| MAC Flooding | Overwhelm switch CAM table | macof | Switch monitoring |
| VLAN Hopping | Access unauthorized VLANs | Yersinia | VLAN configuration audit |

### Layer 3 (Network) Threats
| Threat | Description | Tool | Signature |
|--------|-------------|------|-----------|
| IP Spoofing | Fake source IP | hping3 | Ingress filtering |
| ICMP Attacks | Malicious ICMP packets | ping, hping3 | ICMP rate limiting |
| Route Poisoning | Corrupt routing tables | Custom scripts | Route validation |

### Layer 4 (Transport) Threats
| Threat | Description | Tool | Detection Method |
|--------|-------------|------|----------------|
| SYN Flood | Exhaust connection table | hping3 | SYN cookies, rate limiting |
| Port Scanning | Service discovery | Nmap | Port scan detection |
| TCP Hijacking | Session takeover | Custom tools | Sequence monitoring |

### Layer 5 (Session) Threats
| Threat | Description | Tool | Prevention |
|--------|-------------|------|-----------|
| Session Hijacking | Steal active sessions | Burp Suite | Session tokens, HTTPS |
| NetBIOS Attacks | Windows network attacks | enum4linux | Disable NetBIOS |
| RPC Attacks | Remote procedure calls | rpcclient | RPC hardening |

### Layer 6 (Presentation) Threats
| Threat | Description | Tool | Mitigation |
|--------|-------------|------|-----------|
| SSL/TLS Attacks | Encryption weaknesses | SSLscan | Strong ciphers, updates |
| Data Compression | Compression-based attacks | Custom tools | Disable compression |
| Format String | Input format vulnerabilities | Metasploit | Input validation |

### Layer 7 (Application) Threats
| Threat | Description | Tool | Prevention |
|--------|-------------|------|-----------|
| SQL Injection | Database attacks | sqlmap | Parameterized queries |
| XSS | Client-side code injection | Burp Suite | Input sanitization |
| Buffer Overflow | Memory corruption | Metasploit | DEP, ASLR |

---

## Tools and Techniques by Layer

### Multi-Layer Tools
```
Wireshark: Layers 1-7 (Complete packet analysis)
Nmap: Layers 3-7 (Network discovery, port scanning, service detection)
Metasploit: Layers 3-7 (Exploitation framework)
Burp Suite: Layers 4-7 (Web application security)
```

### Layer-Specific Tool 
| Layer | Primary Tools | Secondary Tools | Specialized Tools |
|-------|---------------|-----------------|-------------------|
| 7 | Burp Suite, OWASP ZAP | Nikto, sqlmap | w3af, dirb |
| 6 | SSLscan, testssl.sh | sslstrip | stunnel, socat |
| 5 | enum4linux, smbclient | rpcclient | nbtscan |
| 4 | Nmap, hping3 | masscan, zmap | unicornscan |
| 3 | hping3, Scapy | traceroute, ping | lft, paris-traceroute |
| 2 | Ettercap, Bettercap | Yersinia, macof | dsniff, arp-scan |
| 1 | Cable testers | RF analyzers | Physical security tools |

---

## Attack Scenarios by Layer

### Scenario 1: Web Application Penetration Test
```
Objective: Test a web application for vulnerabilities

Layer 7 (Application):
- Use Burp Suite to test for SQL injection
- Scan for XSS vulnerabilities with OWASP ZAP
- Test for directory traversal attacks

Layer 6 (Presentation):
- Test SSL/TLS configuration with SSLscan
- Check for weak cipher suites
- Verify certificate validity

Layer 4 (Transport):
- Port scan with Nmap to identify services
- Test for open/filtered ports
- Identify service versions

Layer 3 (Network):
- Traceroute to understand network path
- Test for ICMP responses
- Check for IP-based filtering
```

### Scenario 2: Internal Network Assessment
```
Objective: Assess internal network security

Layer 2 (Data Link):
- ARP scan to discover active hosts
- Test for ARP spoofing capabilities
- Identify switch security features

Layer 3 (Network):
- Network mapping with Nmap
- ICMP sweep for host discovery
- Route enumeration

Layer 4 (Transport):
- Comprehensive port scanning
- Service enumeration
- Banner grabbing

Layer 5 (Session):
- NetBIOS enumeration on Windows hosts
- SMB share enumeration
- RPC endpoint mapping

Layer 7 (Application):
- Web service identification
- Database service discovery
- Email server enumeration
```

### Scenario 3: Wireless Network Testing
```
Objective: Test wireless network security

Layer 1 (Physical):
- RF spectrum analysis
- Signal strength measurement
- Physical access point location

Layer 2 (Data Link):
- WPA/WEP security assessment
- MAC address filtering bypass
- Rogue access point detection

Layer 3 (Network):
- DHCP enumeration
- Gateway identification
- Network segmentation testing

Higher Layers:
- Captive portal bypass
- Traffic interception
- Client attack vectors
```

---

## Common Exam Question Types

### Type 1: Tool-to-Layer Mapping
```
Q: "Which layer does Ettercap primarily operate at?"
A: Layer 2 (Data Link Layer) - ARP spoofing, MAC manipulation

Q: "At which OSI layer does SQL injection occur?"
A: Layer 7 (Application Layer) - Database application attacks

Q: "Nmap's SYN scan operates at which layer?"
A: Layer 4 (Transport Layer) - TCP port scanning
```

### Type 2: Attack Classification
```
Q: "An attacker floods a network with ARP replies containing false 
MAC-to-IP mappings. Which layer attack is this?"
A: Layer 2 attack (ARP spoofing/poisoning)

Q: "A SYN flood attack primarily targets which OSI layer?"
A: Layer 4 (Transport Layer) - TCP connection exhaustion

Q: "SSL stripping attacks operate at which layer?"
A: Layer 6 (Presentation Layer) - Encryption manipulation
```

### Type 3: Protocol Identification
```
Q: "Which protocol operates at the Session layer?"
A: NetBIOS, RPC, PPTP, L2TP

Q: "ICMP operates at which layer?"
A: Layer 3 (Network Layer)

Q: "Where does HTTP operate in the OSI model?"
A: Layer 7 (Application Layer)
```

### Type 4: Scenario-Based Questions
```
Scenario: "During a penetration test, you need to identify all open 
ports on a target system. You decide to use a technique that doesn't 
complete the three-way handshake to remain stealthy."

Q: "Which layer is primarily involved in this scanning technique?"
A: Layer 4 (Transport Layer) - TCP SYN scanning

Q: "Which tool would be most appropriate for this task?"
A: Nmap with -sS (SYN scan) option
```

### Type 5: Defense Mechanism Questions
```
Q: "To prevent ARP spoofing attacks, which layer security measure 
should be implemented?"
A: Layer 2 security - Static ARP entries, ARP monitoring

Q: "What is the primary defense against Layer 7 SQL injection attacks?"
A: Input validation, parameterized queries, WAF

Q: "Which security control helps prevent SYN flood attacks?"
A: SYN cookies, rate limiting (Layer 4 protection)
```

---

## Protocol Analysis

### Layer 2 Protocol Analysis
```
Ethernet Frame Structure:
[Preamble][Dest MAC][Src MAC][Type/Length][Data][FCS]

Key Points for Exam:
- MAC addresses are 48-bit (6 bytes)
- Frame size: 64-1518 bytes
- Collision detection in CSMA/CD
```

### Layer 3 Protocol Analysis
```
IPv4 Header Fields (Exam Focus):
- Version (4 bits): IP version (4 or 6)
- IHL (4 bits): Internet Header Length
- Type of Service (8 bits): QoS marking
- Total Length (16 bits): Packet size
- Identification (16 bits): Fragment identification
- Flags (3 bits): DF (Don't Fragment), MF (More Fragments)
- TTL (8 bits): Time to Live (hop count)
- Protocol (8 bits): Next layer protocol (TCP=6, UDP=17, ICMP=1)
- Source/Destination IP (32 bits each)
```

### Layer 4 Protocol Analysis
```
TCP Header Fields (Critical for Exam):
- Source/Destination Port (16 bits each)
- Sequence Number (32 bits): Data ordering
- Acknowledgment Number (32 bits): Next expected sequence
- Window Size (16 bits): Flow control
- Flags: URG, ACK, PSH, RST, SYN, FIN

UDP Header (Simpler):
- Source/Destination Port (16 bits each)
- Length (16 bits): Header + data length
- Checksum (16 bits): Error detection
```
---

## Quick Reference Tables

### Attack Types by Layer
| Layer | Attack Type | Tool | Difficulty |
|-------|-------------|------|------------|
| 1 | Physical Access | N/A | Low |
| 2 | ARP Spoofing | Ettercap | Medium |
| 3 | IP Spoofing | hping3 | Medium |
| 4 | Port Scanning | Nmap | Low |
| 5 | Session Hijacking | Burp Suite | Hard |
| 6 | SSL Attacks | SSLstrip | Medium |
| 7 | Web App Attacks | Multiple | Varies |

### Common Protocols by Layer
| Layer | Protocol Examples | Key Function |
|-------|-------------------|--------------|
| 7 | HTTP, HTTPS, FTP, SMTP, DNS | User applications |
| 6 | SSL/TLS, JPEG, GIF, ASCII | Encryption, formatting |
| 5 | NetBIOS, RPC, PPTP | Session management |
| 4 | TCP, UDP | Reliable/unreliable transport |
| 3 | IP, ICMP, OSPF, BGP | Routing, addressing |
| 2 | Ethernet, Wi-Fi, ARP | Frame delivery |
| 1 | Cables, Radio waves | Physical transmission |

---

## Exam Strategy & Tips

### High-Priority Topics for CEH v13
1. **Layer 2**: ARP spoofing attacks and tools (Ettercap)
2. **Layer 3**: ICMP attacks, IP spoofing with hping3
3. **Layer 4**: Port scanning techniques with Nmap
4. **Layer 7**: Web application attacks, SQL injection


### Common Trap Answers
- **SSL/TLS confusion**: Remember it's Layer 6 (Presentation), not Layer 7
- **ARP vs ICMP**: ARP is Layer 2, ICMP is Layer 3
- **Port scanning**: Always Layer 4 (Transport), regardless of tool
---
