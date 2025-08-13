# Scanning Techniques For Host Discovery - Overview

## Introduction

Host discovery is the first phase of network reconnaissance where ethical hackers identify live systems on a target network. This process involves sending various types of packets to determine which hosts are active and responsive. Understanding these techniques is crucial for the CEH v13 exam as scanning and enumeration represents 15-20% of the exam content.

## Why Host Discovery is Important

- **Network Mapping**: Identifies the scope and topology of target networks
- **Asset Identification**: Discovers active systems that require further investigation  
- **Attack Surface Assessment**: Determines potential entry points for penetration testing
- **Network Security Assessment**: Helps identify security gaps and misconfigurations

## Categories of Host Discovery Techniques

### 1. ICMP Ping Scan
Internet Control Message Protocol (ICMP) based techniques that use different ICMP message types to identify live hosts.

#### Sub-techniques:
- **ICMP Echo Ping** - Standard ping using Echo Request (Type 8) and Echo Reply (Type 0)
  - **ICMP Echo Ping Sweep** - Automated scanning of multiple IP addresses
- **ICMP Timestamp Ping** - Uses Timestamp Request (Type 13) and Timestamp Reply (Type 14)
- **ICMP Address Mask Ping** - Uses Address Mask Request (Type 17) and Address Mask Reply (Type 18)

### 2. ARP Ping Scan
Address Resolution Protocol (ARP) based discovery technique effective within local network segments.

### 3. UDP Ping Scan
User Datagram Protocol (UDP) based technique that sends UDP packets to closed ports expecting ICMP Port Unreachable responses.

### 4. TCP Ping Scan
Transmission Control Protocol (TCP) based techniques using different TCP flag combinations.

#### Sub-techniques:
- **TCP SYN Ping** - Uses TCP SYN packets to initiate connection attempts
- **TCP ACK Ping** - Uses TCP ACK packets to probe for responses

### 5. IP Protocol Ping Scan
Advanced technique that sends IP packets with different protocol numbers to identify supported protocols on target hosts.

## Key Tools for Host Discovery

- **Nmap** - Primary tool for network discovery and security auditing
- **Hping3** - Custom packet crafting and advanced ping techniques
- **Fping** - Fast ping sweeper for multiple hosts
- **Angry IP Scanner** - GUI-based network scanner
- **Masscan** - High-speed port scanner with host discovery capabilities

## Exam Tips

- Understand the difference between each scanning technique and when to use them
- Know which techniques work best in different network environments
- Be familiar with firewall evasion techniques for each scan type
- Understand the limitations and advantages of each method
- Practice identifying scan types from packet captures and tool outputs

## Network Environment Considerations

- **Local Network**: ARP ping scans are most effective
- **Internet Scanning**: ICMP and TCP ping scans preferred
- **Firewalled Networks**: TCP ACK and advanced techniques required
- **Stealth Requirements**: Careful selection of scan types and timing

## Next Steps

Each scanning technique will be covered in detail in separate documentation files. This overview provides the foundation for understanding how these techniques fit together in the reconnaissance phase of ethical hacking.

---
