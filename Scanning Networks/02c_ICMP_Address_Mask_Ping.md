# ICMP Address Mask Ping

## Definition

ICMP Address Mask Ping is a specialized host discovery technique that uses ICMP Address Mask Request messages (Type 17) to identify live hosts. This method requests subnet mask information from target systems, which should respond with ICMP Address Mask Reply messages (Type 18) containing their subnet mask configuration. It's particularly useful for firewall evasion and network reconnaissance when standard ping methods are blocked.

## How ICMP Address Mask Ping Works

### Basic Process:
1. **Source Host** sends ICMP Address Mask Request packet (Type 17, Code 0)
2. **Target Host** receives the address mask request
3. **Target Host** processes request and determines appropriate subnet mask
4. **Target Host** sends ICMP Address Mask Reply (Type 18, Code 0) with mask information
5. **Source Host** receives reply, confirming target is alive and may extract network info

### Packet Structure:
- **IP Header**: Source and destination IP addresses
- **ICMP Header**: Type 17 (Address Mask Request), Code 0, Checksum, Identifier, Sequence Number
- **Address Mask Field**: 32-bit field for subnet mask (0x00000000 in request)
- **Reply Contains**: Actual subnet mask of responding system

## ICMP Message Types

| Type | Code | Description |
|------|------|-------------|
| 17   | 0    | Address Mask Request |
| 18   | 0    | Address Mask Reply |

## Tools and Commands

### Nmap ICMP Address Mask Ping
```bash
# ICMP Address Mask ping scan
nmap -PM target_ip

# Address Mask ping for IP range
nmap -sn -PM 192.168.1.0/24

# Combined with other ping types
nmap -sn -PE -PM 192.168.1.1

# Verbose address mask ping scan
nmap -sn -PM -v 192.168.1.0/24
```

### Hping3 Address Mask Requests
```bash
# Send ICMP address mask request
hping3 -1 -C 17 target_ip

# Address mask request with count
hping3 -1 -C 17 -c 3 192.168.1.1

# Address mask request with custom data
hping3 -1 -C 17 -d 4 192.168.1.1
```

## Address Mask Information

### Subnet Mask Format:
- **32-bit Value**: Standard subnet mask representation
- **Common Masks**: 
  - 255.255.255.0 (0xFFFFFF00) - /24 network
  - 255.255.0.0 (0xFFFF0000) - /16 network  
  - 255.0.0.0 (0xFF000000) - /8 network

### Information Disclosure:
- **Network Topology**: Reveals subnet structure
- **Network Size**: Indicates number of possible hosts
- **Routing Information**: Helps understand network boundaries
- **VLSM Usage**: Shows variable length subnet masking

## Advantages

- **Firewall Evasion**: Often bypasses filters blocking Echo/Timestamp
- **Rare Usage**: Less commonly monitored than other ICMP types
- **Network Intelligence**: Provides valuable subnet mask information
- **Alternative Discovery**: Works when other methods fail
- **Legacy Support**: Supported by older systems and network devices
- **Information Gathering**: Dual purpose of host discovery and reconnaissance

## Limitations

- **Deprecated Protocol**: Many modern systems don't respond to mask requests
- **Security Concerns**: Considered information disclosure vulnerability
- **Limited Implementation**: Not widely supported on current operating systems
- **Firewall Blocking**: Advanced firewalls may filter these requests
- **False Negatives**: Host may be alive but not supporting mask requests
- **Router Dependency**: Often only routers respond to these requests

## System Response Behaviors

### Legacy Systems:
- **Older Windows**: May respond with subnet mask information
- **Classic Unix/Linux**: Often implemented address mask responses
- **Network Equipment**: Routers frequently support mask requests

### Modern Systems:
- **Windows 10/11**: Address mask responses typically disabled
- **Current Linux**: Usually disabled by default for security
- **Mobile Devices**: Generally don't support mask requests
- **Security Appliances**: May respond depending on configuration

### Network Infrastructure:
- **Routers**: Most likely to respond with accurate subnet masks
- **Layer 3 Switches**: May respond based on configuration
- **Firewalls**: Response depends on security policy
- **Load Balancers**: Varies by vendor and configuration

## Security Implications

### Information Disclosure Risks:
- **Network Topology**: Reveals network architecture details
- **Subnet Information**: Exposes network segmentation
- **Host Enumeration**: Helps calculate total possible hosts
- **Routing Intelligence**: Assists in understanding network paths

### For Defenders:
- **Disable Responses**: Turn off ICMP address mask replies
- **Monitor Requests**: Watch for reconnaissance patterns
- **Information Policy**: Assess what network info should be public
- **Network Hardening**: Implement appropriate ICMP filtering

### For Penetration Testers:
- **Network Mapping**: Use mask info for network understanding
- **Host Discovery**: Alternative when other methods blocked
- **Infrastructure Analysis**: Identify network device types
- **Reconnaissance Phase**: Gather network topology intelligence

## Detection and Response

### Detection Methods:
- **IDS Signatures**: Monitor for Type 17 ICMP packets
- **Network Analysis**: Unusual address mask request patterns
- **Log Monitoring**: System logs showing mask request processing
- **Anomaly Detection**: Unexpected volumes of mask requests

### Response Analysis:
```
# Successful Address Mask Response
ICMP Address Mask Request to 192.168.1.1
Response: Type 18 (Address Mask Reply)
Subnet Mask: 255.255.255.0 (/24 network)
Host confirmed alive with network information

# No Response (Filtered or Unsupported)
ICMP Address Mask Request to 192.168.1.1
No response received (likely filtered or unsupported)

# ICMP Unreachable Response
ICMP Address Mask Request to 192.168.1.1
ICMP Destination Unreachable (Protocol Unreachable)
```

## Practical Applications

### Network Reconnaissance:
- **Subnet Discovery**: Identify network boundaries and sizes
- **Device Identification**: Routers more likely to respond
- **Network Mapping**: Build comprehensive network topology
- **Security Assessment**: Test information disclosure controls

### Penetration Testing:
- **Stealth Discovery**: Alternative to more common ping methods
- **Firewall Testing**: Assess ICMP filtering completeness
- **Information Gathering**: Collect network architecture data
- **Target Prioritization**: Identify critical network infrastructure


## CEH Exam Focus Points

- Understand ICMP Address Mask message types (17 and 18)
- Know when address mask ping might work vs. other methods
- Recognize security implications of address mask responses
- Understand network information disclosed by subnet masks
- Be familiar with Nmap -PM option for address mask ping
- Know why this technique is less reliable on modern systems
- Understand relationship between subnet masks and network topology
---
