# UDP Ping Scan

## Definition

UDP Ping Scan is a host discovery technique that uses UDP (User Datagram Protocol) packets to identify live hosts. This method sends UDP packets to specific ports on target systems and analyzes responses to determine host availability. Unlike ICMP ping, UDP ping can provide information about both host status and service availability, making it useful for firewall evasion when ICMP traffic is blocked. The technique relies on UDP's connectionless nature and various response patterns from different services.

## How UDP Ping Scan Works

### Basic Process:
1. **Source Host** sends UDP packet to specific port on target
2. **Target Host** receives UDP packet and processes based on port status
3. **Target Host** responds with appropriate packet (service response or ICMP error)
4. **Source Host** analyzes response type to determine host and service status
5. **Source Host** uses response timing and content for host discovery

### Packet Structure:
- **IP Header**: Source and destination IP addresses
- **UDP Header**: Source port, destination port, length, checksum
- **UDP Data**: Optional payload data for specific services
- **Response**: Service data, ICMP Port Unreachable, or timeout

## Common UDP Ping Ports

| Port | Service | Response Type |
|------|---------|---------------|
| 53 | DNS | Service response or error |
| 67 | DHCP | Service response (if DHCP server) |
| 69 | TFTP | Service response or error |
| 123 | NTP | Time synchronization response |
| 161 | SNMP | Management response or timeout |
| 500 | IPSec | Security association response |

## Tools and Commands

### Nmap UDP Ping Scan
```bash
# UDP ping to port 53 (DNS)
nmap -sn -PU53 192.168.1.0/24

# UDP ping to multiple ports
nmap -sn -PU53,123,161 192.168.1.1

# UDP ping with custom port
nmap -sn -PU69 192.168.1.0/24

# Combined UDP ping scan
nmap -sn -PE -PU53 192.168.1.0/24
```

### Hping3 UDP Packets
```bash
# UDP ping to DNS port
hping3 -2 -p 53 -c 3 192.168.1.1

# UDP ping with data payload
hping3 -2 -p 53 -d 32 192.168.1.1

# UDP ping to NTP port
hping3 -2 -p 123 -c 5 192.168.1.1

# UDP flood test
hping3 -2 -p 53 --flood 192.168.1.1
```

### Netcat UDP Testing
```bash
# UDP connection test
nc -u 192.168.1.1 53

# UDP with timeout
timeout 5 nc -u 192.168.1.1 123

# UDP with verbose output
nc -uv 192.168.1.1 161
```

## UDP Response Types

### Positive Responses:
- **Service Response**: Application sends back data (host alive, service running)
- **Connection Established**: UDP socket accepts and processes data
- **Protocol Response**: Service-specific acknowledgment or data

### Negative Responses:
- **ICMP Port Unreachable**: Port closed but host alive (Type 3, Code 3)
- **ICMP Host Unreachable**: Host not reachable (Type 3, Code 1)
- **ICMP Network Unreachable**: Network routing issue (Type 3, Code 0)

### No Response Scenarios:
- **Filtered**: Firewall drops packets silently
- **Host Down**: No response due to host being offline
- **Service Timeout**: Application doesn't respond to unexpected data

## Advantages

- **Firewall Evasion**: Bypasses ICMP-blocking firewalls
- **Service Discovery**: Identifies both hosts and running services
- **Port Information**: Determines UDP port status simultaneously
- **Diverse Targets**: Different services respond differently
- **Network Traversal**: UDP packets can traverse NAT/firewalls more easily
- **Stealth Options**: Can appear as legitimate service requests

## Limitations

- **Inconsistent Responses**: UDP services respond differently to unexpected data
- **False Negatives**: Many services don't respond to arbitrary UDP data
- **Firewall Filtering**: Stateful firewalls may block UDP responses
- **Service Dependencies**: Effectiveness depends on target running UDP services
- **Slower Scanning**: May require longer timeouts for accurate results
- **Rate Limiting**: Some systems limit UDP response rates

## System Response Behaviors

### DNS Servers (Port 53):
- **Bind/Named**: May respond with DNS error messages
- **Windows DNS**: Often responds to malformed queries
- **Recursive Resolvers**: May process or reject invalid queries
- **Authoritative Servers**: Response depends on query content

### NTP Servers (Port 123):
- **Standard NTP**: Responds to time requests with current time
- **Secure NTP**: May require authentication for responses
- **Public Time Servers**: Usually respond to basic queries
- **Restricted NTP**: May filter based on source IP

### SNMP Services (Port 161):
- **SNMP v1/v2c**: Responds to community string queries
- **SNMP v3**: Requires proper authentication
- **Network Equipment**: Routers/switches often have SNMP enabled
- **Secured SNMP**: May only respond to authorized sources

### DHCP Servers (Port 67):
- **Active DHCP**: Responds to DHCP discover messages
- **Relay Agents**: Forward requests to actual DHCP servers
- **Rogue DHCP**: Unauthorized servers may respond
- **Secured DHCP**: May implement MAC address filtering

## Security Implications

### Information Disclosure:
- **Service Enumeration**: Reveals running UDP services
- **Version Information**: Some services leak version details
- **Network Topology**: Response times indicate network paths
- **System Identification**: Service banners may reveal OS information

### For Defenders:
- **UDP Monitoring**: Track unusual UDP traffic patterns
- **Service Hardening**: Minimize unnecessary UDP service exposure
- **Firewall Rules**: Implement proper UDP filtering policies
- **Response Analysis**: Monitor for reconnaissance patterns

### Attack Vectors:
- **Service Exploitation**: Identify vulnerable UDP services
- **Denial of Service**: UDP flood attacks against services
- **Amplification Attacks**: Use UDP services for traffic amplification
- **Information Gathering**: Collect service and system details

## Detection and Response

### Detection Methods:
- **Traffic Analysis**: Monitor UDP packet patterns and destinations
- **Service Logs**: Check application logs for unusual requests
- **Network IDS**: Signatures for UDP reconnaissance patterns
- **Anomaly Detection**: Unusual UDP traffic volumes or patterns

### Response Analysis:
```
# Service Response (DNS Example)
UDP packet to 192.168.1.1:53
Response: DNS error message
Host alive, DNS service running

# ICMP Port Unreachable
UDP packet to 192.168.1.1:69
ICMP Type 3 Code 3 response
Host alive, port 69 closed

# No Response (Filtered)
UDP packet to 192.168.1.1:161
No response received
Host status unknown (filtered/down)

# Service-Specific Response (NTP)
UDP packet to 192.168.1.1:123
NTP time response received
Host alive, NTP service active
```

## Practical Applications

### Network Discovery:
- **Service Mapping**: Identify UDP services across network
- **Host Enumeration**: Discover active systems via UDP responses
- **Network Segmentation Testing**: Verify UDP traffic filtering
- **Asset Inventory**: Catalog UDP services and versions

### Penetration Testing:
- **Firewall Bypass**: Alternative when ICMP is blocked
- **Service Identification**: Locate potential attack targets
- **Network Reconnaissance**: Map UDP service landscape
- **Vulnerability Assessment**: Identify exposed UDP services

### System Administration:
- **Service Monitoring**: Verify UDP service availability
- **Network Troubleshooting**: Test UDP connectivity paths
- **Configuration Validation**: Confirm service bindings
- **Performance Testing**: Measure UDP response times

## CEH Exam Focus Points

- Understand UDP is connectionless and stateless protocol
- Know common UDP ports used for ping scanning (53, 123, 161)
- Recognize ICMP Port Unreachable indicates host is alive
- Understand Nmap -PU flag for UDP ping scans
- Know UDP ping can reveal both host status and service information
- Recognize limitations of UDP ping due to service response variability
- Understand UDP ping is useful when ICMP is blocked
---
