# Sniffing Concepts and Network Attacks

## 🎯 Objective

This module starts with an overview of **sniffing concepts** and provides insight into **MAC**, **DHCP**, **ARP**, **MAC Spoofing**, and **DNS Poisoning** attacks. It then discusses various **sniffing tools**, **countermeasures**, and **detection techniques**.

---

## 1. Summarize Sniffing Concepts

### a. Network Sniffing
- Monitoring and capturing network packets.
- Purpose: Intercept traffic for analysis (legitimate or malicious).
- Works by putting NIC into **promiscuous mode**.

### b. How a Sniffer Works
- NIC → Promiscuous Mode → Capture All Packets → Analyze.
- Operates at **Data Link Layer (Layer 2)**.

### c. Types of Sniffing
- **Passive**: Listens only (hubs/wireless), hard to detect.
- **Active**: Injects packets (used on switches), easier to detect.

### d. How an Attacker Hacks a Network Using Sniffers
- Steps: Recon → Access → Deploy Tools → Capture → Extract Data.
- Targets: Passwords, tokens, confidential communications.
- Tools: Wireshark, tcpdump, etc.

### e. Protocols Vulnerable to Sniffing
- Vulnerable: HTTP, FTP, Telnet, SMTP, POP3, SNMP v1/v2.
- Secure: HTTPS, SSH, SFTP, SNMP v3.
- Ports: HTTP(80), HTTPS(443), SNMP(161).

### f. Sniffing in the Data Link Layer of OSI
- Captures frames, MAC addresses, headers, and payload.
- Switches limit visibility via **CAM tables**.

### g. SPAN Port
- Mirrors traffic to a monitoring port.
- Types: Local SPAN, RSPAN, ERSPAN.
- Requires admin rights, read-only access.

---

## 2. Demonstrate Different Sniffing Techniques

### a. MAC Address / CAM Table
- Stores MAC-to-port mappings in switches.

### b. What Happens When CAM Table is Full
- Switch floods traffic (acts like a hub), enabling sniffing.

### c. MAC Flooding
- Overloads CAM table with fake MACs, forcing traffic to broadcast.

### d. Switch Port Stealing
- Attacker hijacks an active port by spoofing legitimate MAC.

### e. How to Defend Against MAC Attacks
- Use port security, dynamic ARP inspection, and MAC filtering.

### f. DHCP Starvation Attack
- Flood DHCP server with fake requests, exhausting IP pool.

### g. Rogue DHCP Server Attack
- Attacker sets up fake DHCP server to redirect traffic.

### h. ARP Spoofing Attack
- Sends fake ARP messages to intercept or redirect traffic.

### i. Configuring DHCP Spoofing & Dynamic ARP Inspection
- Network configuration to block spoofed DHCP/ARP traffic.

### j. MAC Spoofing / Duplicating
- Changing the MAC address to bypass filters or impersonate a device.

### k. IRDP Spoofing
- Spoofing router discovery messages to mislead hosts.

### l. VLAN Hopping
- Attacker jumps from one VLAN to another via tagging/trunking tricks.

### m. STP Attack
- Exploits Spanning Tree Protocol to become the root bridge and manipulate traffic flow.

### n. DNS Poisoning Techniques
- Alter DNS responses to redirect users to malicious sites.

### o. Internet DNS Spoofing
- Spoof DNS responses across the Internet or between servers.

### p. Proxy Server DNS Poisoning
- Poison DNS cache on a proxy to redirect traffic.

### q. DNS Cache Poisoning
- Corrupts DNS resolver cache with false information.

---

## 3. Use Sniffing Tools

### a. Wireshark
- GUI-based packet analyzer for network troubleshooting and inspection.

### b. Different Sniffing Tools
- Examples: 
  - tcpdump
  - Ettercap
  - Cain & Abel
  - Ngrep
  - Kismet
  - Tshark

---

## 4. Explain Sniffing Countermeasures

### a. How to Detect Sniffing
- Monitor traffic anomalies, ARP inconsistencies, or broadcast behavior.

### b. Promiscuous Mode Detection Tools
- **Tools**:
  - Nmap (with specific scripts)
  - AntiSniff
  - Wireshark (for detection signatures)
  - Snort (IDS rules)

---

> ✅ *This structured breakdown helps in understanding sniffing, its threats, and defense mechanisms in modern networks. Ideal for training, security audits, and educational modules.*



  
