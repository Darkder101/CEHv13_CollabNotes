# TCP ACK Ping

## Definition

TCP ACK Ping is a host discovery technique that uses TCP ACK packets to determine if a target host is alive and responsive. This method sends TCP ACK packets (acknowledgment packets) to target systems without establishing a prior connection, analyzing the responses to confirm host availability. It's particularly effective for bypassing stateless firewalls and packet filters that may block SYN packets but allow ACK packets.

## How TCP ACK Ping Works

### Basic Process:
1. **Source Host** sends TCP ACK packet to target port (commonly port 80)
2. **Target Host** receives the unsolicited ACK packet
3. **Target Host** processes the unexpected ACK packet
4. **Target Host** sends TCP RST packet (connection not established)
5. **Source Host** receives RST response, confirming target is alive
6. **Analysis**: RST response indicates active host regardless of port state

### Packet Structure:
- **IP Header**: Source and destination IP addresses
- **TCP Header**: Source port, destination port, sequence number, ACK flag set
- **TCP Flags**: ACK bit set (0x10)
- **Response Expected**: TCP RST packet indicating no established connection

## TCP Response Analysis

| Response Type | TCP Flags | Meaning |
|---------------|-----------|---------|
| RST | RST (0x04) | Host alive (expected response) |
| No Response | - | Filtered by firewall or host down |
| ICMP Unreachable | - | Router/firewall blocking with ICMP |

## Tools and Commands

### Nmap TCP ACK Ping
```bash
# Default TCP ACK ping (port 80)
nmap -PA target_ip

# TCP ACK ping to specific port
nmap -PA22 192.168.1.1

# TCP ACK ping to multiple ports
nmap -PA22,80,443 192.168.1.1

# ACK ping for IP range
nmap -sn -PA80 192.168.1.0/24

# Combined ACK ping with other techniques
nmap -sn -PS80 -PA80 192.168.1.1

# Verbose ACK ping scan
nmap -sn -PA80 -v 192.168.1.0/24
```

### Hping3 TCP ACK Requests
```bash
# Send TCP ACK packet
hping3 -A -p 80 target_ip

# ACK packet with count
hping3 -A -p 80 -c 3 192.168.1.1

# ACK with custom sequence number
hping3 -A -p 80 -M 1234 192.168.1.1

# ACK with custom source port
hping3 -A -s 12345 -p 80 192.168.1.1
```

## Firewall Evasion Principles

### Stateless Firewall Behavior:
- **Outbound Rules**: May allow ACK packets assuming they're responses
- **Connection Tracking**: Stateless filters can't track connection state
- **Rule Bypass**: ACK packets may bypass "no new connections" rules
- **Asymmetric Routing**: Works when return path differs from forward path

### Stateful vs. Stateless Filtering:
- **Stateful Firewalls**: Track connection state, block unsolicited ACK
- **Stateless Firewalls**: Process packets independently, may allow ACK
- **Packet Filters**: Simple rule-based systems vulnerable to ACK bypass
- **Application Gateways**: Typically block unsolicited ACK packets

## Advantages

- **Firewall Evasion**: Bypasses some stateless firewall rules
- **Stealth Factor**: Less commonly monitored than SYN packets
- **Fast Scanning**: Immediate RST response provides quick results
- **Universal Response**: All live hosts respond with RST to unsolicited ACK
- **No Connection State**: Doesn't consume connection table entries
- **Logging Minimal**: May generate fewer security alerts

## Limitations

- **Stateful Filtering**: Blocked by modern stateful firewalls
- **Limited Effectiveness**: Many current firewalls handle ACK filtering
- **No Port Information**: Cannot determine if ports are open or closed
- **Detection Risk**: Security systems may flag unsolicited ACK packets
- **False Positives**: May receive RST from intermediate devices
- **Protocol Dependency**: Requires TCP stack processing

## System Response Behaviors

### Normal Host Response:
- **TCP RST**: Standard response to unsolicited ACK packet
- **Immediate**: RST sent immediately without application involvement
- **No Logging**: May not generate application-level logs
- **Stack Processing**: Handled at TCP/IP stack level

### Firewall Responses:
- **Stateful Firewall**: Drops packet (no connection state exists)
- **Stateless Allow**: Forwards packet to host, RST returned
- **Stateless Block**: Drops packet or sends ICMP unreachable
- **Proxy Firewall**: May respond with own RST packet

### Network Device Responses:
- **Routers**: Forward packet based on routing table
- **Load Balancers**: May respond based on configuration
- **IDS/IPS**: May block or alert on unsolicited ACK patterns
- **NAT Devices**: May drop packets without connection state

## Security Implications

### Information Disclosure:
- **Host Discovery**: Confirms presence of live systems
- **Firewall Testing**: Tests filtering rule effectiveness
- **Network Mapping**: Identifies reachable network segments
- **Response Timing**: May reveal network topology information

### For Defenders:
- **Stateful Filtering**: Implement stateful firewall rules
- **Connection Tracking**: Use connection state monitoring
- **Alert Tuning**: Monitor for unsolicited ACK patterns
- **Network Segmentation**: Limit broadcast domains for scanning

### For Penetration Testers:
- **Firewall Bypass**: Alternative when SYN scanning fails
- **Stealth Discovery**: Less obvious than traditional ping methods
- **Network Assessment**: Test firewall configuration quality
- **Reconnaissance**: Identify filtering mechanisms in use

## Detection and Response

### Detection Methods:
- **IDS Signatures**: Monitor for TCP ACK without prior SYN
- **Behavioral Analysis**: Unusual ACK packet patterns
- **Connection State**: ACK packets without established connections
- **Rate Monitoring**: High frequency ACK packets from single source

### Response Patterns:
```
# Successful ACK Ping
TCP ACK to 192.168.1.1:80
Response: TCP RST from 192.168.1.1:80
Host confirmed alive

# Filtered ACK Ping
TCP ACK to 192.168.1.1:80
No response received (likely filtered)

# ICMP Response
TCP ACK to 192.168.1.1:80
ICMP Destination Unreachable (Protocol Unreachable)
```

## Firewall Rule Testing

### Testing Scenarios:
- **Inbound ACK Allow**: Rule allows ACK packets inbound
- **Outbound State**: Firewall assumes ACK is response to outbound connection
- **Bidirectional Rules**: Separate rules for each direction
- **Protocol-Specific**: Different handling for TCP vs. UDP

### Rule Analysis:
```
# Vulnerable Stateless Rule
allow tcp any any -> internal_net any (flags: A)

# Secure Stateful Rule  
allow tcp any any -> internal_net any (established)

# Restrictive Rule
deny tcp any any -> internal_net any (flags: !S,A)
```

## Practical Applications

### Network Security Assessment:
- **Firewall Testing**: Evaluate filtering rule completeness
- **Host Discovery**: Find live systems behind packet filters
- **Network Reconnaissance**: Map accessible network segments
- **Security Posture**: Assess overall network security configuration

### Penetration Testing:
- **Stealth Scanning**: Alternative discovery when SYN is blocked
- **Filter Evasion**: Bypass specific firewall configurations
- **Network Mapping**: Build comprehensive network topology
- **Vulnerability Assessment**: Identify configuration weaknesses

## CEH Exam Focus Points

- Understand TCP ACK ping vs. TCP SYN ping differences
- Know when ACK ping is effective (stateless firewalls)
- Recognize that ACK ping always expects RST response
- Understand stateful vs. stateless firewall behavior with ACK packets
- Be familiar with Nmap -PA option and syntax
- Know limitations of ACK ping with modern security systems
- Understand why unsolicited ACK packets generate RST responses
- Recognize detection methods for TCP ACK scanning
