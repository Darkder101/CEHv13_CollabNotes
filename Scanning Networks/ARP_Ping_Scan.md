# ARP Ping Scan

## Definition

ARP Ping Scan is a host discovery technique that uses Address Resolution Protocol (ARP) requests to identify live hosts on the local network segment. This method sends ARP requests asking "Who has this IP address?" and waits for ARP replies, which can only come from hosts that are actually present and active on the same Layer 2 network. ARP ping is highly reliable for local network discovery since ARP operates at the data link layer and bypasses most firewall restrictions.

## How ARP Ping Scan Works

### Basic Process:
1. **Source Host** sends ARP Request packet asking for MAC address of target IP
2. **Network Switch** broadcasts ARP request to all ports in VLAN/segment  
3. **Target Host** receives ARP request and checks if IP matches its configuration
4. **Target Host** sends ARP Reply with its MAC address back to source
5. **Source Host** receives ARP reply, confirming target is alive and obtains MAC address

### Packet Structure:
- **Ethernet Header**: Source and destination MAC addresses
- **ARP Header**: Hardware type, Protocol type, Operation code
- **ARP Request**: Sender IP/MAC, Target IP (Target MAC = 00:00:00:00:00:00)
- **ARP Reply**: Sender IP/MAC, Target IP/MAC with actual MAC address

## ARP Message Types

| Operation Code | Type | Description |
|---------------|------|-------------|
| 1 | ARP Request | "Who has this IP address?" |
| 2 | ARP Reply | "I have this IP address, here's my MAC" |

## Tools and Commands

### Nmap ARP Ping Scan
```bash
# ARP ping scan for local subnet
nmap -sn -PR 192.168.1.0/24

# ARP ping only (disable other ping types)
nmap -sn -PR --disable-arp-ping 192.168.1.0/24

# ARP ping with port scan
nmap -PR 192.168.1.1-50

# Verbose ARP ping scan
nmap -sn -PR -v 192.168.1.0/24
```

### Arping Command
```bash
# Basic ARP ping
arping -c 3 192.168.1.1

# ARP ping with interface specification
arping -I eth0 192.168.1.1

# ARP ping with timeout
arping -w 2 192.168.1.1

# Continuous ARP ping
arping 192.168.1.1
```

### Netdiscover Tool
```bash
# Passive ARP discovery
netdiscover -p

# Active ARP scan on subnet
netdiscover -r 192.168.1.0/24

# ARP scan with specific interface
netdiscover -i eth0 -r 192.168.1.0/24
```

## ARP Protocol Details

### Hardware Types:
- **Ethernet (1)**: Most common for LAN networks
- **IEEE 802.11**: Wireless networks  
- **Token Ring (6)**: Legacy network technology

### Protocol Types:
- **IPv4 (0x0800)**: Standard IP protocol
- **IPv6 (0x86DD)**: Next generation IP

### Address Information:
- **MAC Address**: 6-byte hardware identifier
- **IP Address**: 4-byte logical network address
- **Broadcast MAC**: FF:FF:FF:FF:FF:FF for ARP requests

## Advantages

- **Layer 2 Operation**: Cannot be blocked by most firewalls
- **100% Accuracy**: If host responds, it's definitely alive and reachable
- **Fast Discovery**: No need to wait for timeouts on dead hosts
- **MAC Address Collection**: Provides hardware addresses for further analysis
- **Local Network Only**: Ideal for subnet discovery and enumeration
- **No Port Dependencies**: Works regardless of running services

## Limitations

- **Local Segment Only**: Cannot traverse routers (Layer 3 boundary)
- **Same Subnet Requirement**: Source and target must be on same network
- **Physical Network Dependency**: Requires direct Layer 2 connectivity
- **VLAN Restrictions**: Limited to same VLAN or broadcast domain
- **No Remote Discovery**: Cannot discover hosts across WAN connections
- **Switch Dependencies**: May not work across certain network configurations

## System Response Behaviors

### Standard Responses:
- **Windows Systems**: Respond to ARP requests for configured IP
- **Linux/Unix**: Reply with MAC address when IP matches interface
- **Network Devices**: Routers, switches respond for their interface IPs
- **Mobile Devices**: Smartphones, tablets respond normally

### Special Cases:
- **Proxy ARP**: Routers may respond for other networks
- **ARP Spoofing Protection**: Some systems validate ARP consistency
- **Static ARP Entries**: May not respond to requests for static entries
- **Virtual Interfaces**: VMs respond through hypervisor networking

### Network Infrastructure:
- **Managed Switches**: Forward ARP requests within VLAN
- **Routers**: Respond only for directly connected interfaces
- **Firewalls**: Cannot filter ARP (operates below IP layer)
- **Wireless Access Points**: Bridge ARP between wireless and wired

## Security Implications

### Information Disclosure:
- **MAC Address Exposure**: Reveals hardware vendor information
- **Network Topology**: Shows active hosts on local segment
- **Device Identification**: MAC prefixes identify device manufacturers
- **Network Mapping**: Enables comprehensive local network mapping

### For Defenders:
- **ARP Monitoring**: Watch for unusual ARP request patterns
- **Static ARP Tables**: Use static entries for critical systems
- **Port Security**: Configure switch port security for MAC addresses
- **ARP Inspection**: Enable Dynamic ARP Inspection on switches

### Attack Vectors:
- **ARP Spoofing**: Impersonate other devices on network
- **Man-in-the-Middle**: Redirect traffic through attacker system
- **Network Discovery**: Map all active hosts on local segment
- **Device Fingerprinting**: Identify device types through MAC addresses

## Detection and Response

### Detection Methods:
- **Network Monitoring**: Capture ARP traffic patterns
- **ARP Table Analysis**: Monitor ARP cache changes
- **Switch Logs**: Review ARP learning and forwarding logs
- **Anomaly Detection**: Identify unusual ARP request volumes

### Response Analysis:
```
# Successful ARP Response
ARP Request for 192.168.1.100
ARP Reply from 00:1B:44:11:3A:B7
Host confirmed alive with MAC address

# No ARP Response  
ARP Request for 192.168.1.200
No reply received (host likely offline/non-existent)

# Duplicate IP Detection
Multiple ARP replies for same IP address
Potential IP conflict or ARP spoofing
```

## Practical Applications

### Network Administration:
- **IP Conflict Detection**: Identify duplicate IP addresses
- **Asset Discovery**: Map all devices on local network
- **Network Troubleshooting**: Verify Layer 2 connectivity
- **Device Inventory**: Collect MAC addresses for asset management

### Security Assessment:
- **Local Network Mapping**: Discover all active hosts
- **Rogue Device Detection**: Identify unauthorized devices
- **Network Segmentation Testing**: Verify VLAN boundaries
- **Incident Response**: Trace MAC addresses during investigations

### Penetration Testing:
- **Initial Discovery**: Identify targets on local network
- **Network Reconnaissance**: Map local infrastructure
- **Lateral Movement**: Discover additional targets after compromise
- **ARP Poisoning Setup**: Identify targets for man-in-the-middle attacks

## CEH Exam Focus Points

- Understand ARP operates at Layer 2 (Data Link)
- Know ARP requests are broadcast, replies are unicast
- Remember ARP ping only works on local network segment
- Understand why firewalls cannot block ARP requests
- Know Nmap uses -PR flag for ARP ping scans
- Recognize ARP provides MAC addresses along with host discovery
- Understand limitations of ARP across routed networks
---
