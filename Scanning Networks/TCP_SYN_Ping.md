# TCP SYN Ping

## Definition

TCP SYN Ping is a host discovery technique that uses TCP SYN packets to determine if a target host is alive and responsive. Unlike traditional ICMP ping, this method sends TCP SYN packets to specific ports on target systems and analyzes the responses to confirm host availability. It's particularly effective for bypassing firewalls that block ICMP traffic while allowing TCP connections.

## How TCP SYN Ping Works

### Basic Process:
1. **Source Host** sends TCP SYN packet to target port (commonly port 80)
2. **Target Host** receives the SYN packet
3. **Target Host** processes the connection request
4. **Target Host** sends TCP SYN-ACK if port is open, or TCP RST if port is closed
5. **Source Host** receives response, confirming target is alive
6. **Source Host** may send RST to close connection gracefully

### Packet Structure:
- **IP Header**: Source and destination IP addresses
- **TCP Header**: Source port, destination port, sequence number, SYN flag set
- **TCP Flags**: SYN bit set (0x02)
- **Response Analysis**: SYN-ACK or RST indicates live host

## TCP Flag Analysis

| Response Type | TCP Flags | Meaning |
|---------------|-----------|---------|
| SYN-ACK | SYN + ACK (0x12) | Port open, host alive |
| RST | RST (0x04) | Port closed, host alive |
| No Response | - | Host down or filtered |

## Tools and Commands

### Nmap TCP SYN Ping
```bash
# Default TCP SYN ping (port 80)
nmap -PS target_ip

# TCP SYN ping to specific port
nmap -PS22 192.168.1.1

# TCP SYN ping to multiple ports
nmap -PS22,80,443 192.168.1.1

# SYN ping for IP range
nmap -sn -PS80 192.168.1.0/24

# Combined SYN ping with port scan
nmap -PS80 -p 1-1000 192.168.1.1

# Verbose SYN ping scan
nmap -sn -PS80 -v 192.168.1.0/24
```

### Hping3 TCP SYN Requests
```bash
# Send TCP SYN packet
hping3 -S -p 80 target_ip

# SYN packet with count
hping3 -S -p 80 -c 3 192.168.1.1

# SYN with custom source port
hping3 -S -s 12345 -p 80 192.168.1.1

# SYN flood simulation
hping3 -S -p 80 --flood 192.168.1.1
```

### Netcat TCP Connection Testing
```bash
# Test TCP connectivity
nc -v -z 192.168.1.1 80

# Test multiple ports
nc -v -z 192.168.1.1 22 80 443

# TCP connection with timeout
timeout 3 nc -v 192.168.1.1 80
```

## Port Selection Strategy

### Common Target Ports:
- **Port 80 (HTTP)**: Most commonly open web service port
- **Port 443 (HTTPS)**: Secure web service, often open
- **Port 22 (SSH)**: Administrative access, frequently available
- **Port 21 (FTP)**: File transfer protocol
- **Port 25 (SMTP)**: Email service
- **Port 53 (DNS)**: Domain name service
- **Port 135 (RPC)**: Windows RPC endpoint mapper

### Port Selection Considerations:
- **Service Likelihood**: Choose ports likely to be open
- **Firewall Rules**: Consider common firewall allow policies  
- **Network Type**: Different ports for servers vs. workstations
- **Industry Standards**: Specific ports for different industries

## Advantages

- **Firewall Evasion**: Bypasses ICMP-blocking firewalls
- **Accurate Results**: TCP responses are more reliable than ICMP
- **Port Information**: Simultaneously tests port availability
- **Stateful Filtering**: Works through stateful firewalls
- **Universal Support**: TCP is supported by all network devices
- **Stealth Potential**: Appears as legitimate connection attempt

## Limitations

- **Port Dependency**: Requires knowledge of likely open ports
- **Slower Performance**: TCP handshake adds latency
- **Resource Usage**: More network and system resources required
- **Firewall Detection**: May trigger security alerts
- **Connection Logs**: Creates entries in target system logs
- **State Tracking**: Consumes connection table entries

## System Response Behaviors

### Open Port Response:
- **TCP SYN-ACK**: Port is open and accepting connections
- **Followed by**: Source should send RST to avoid full connection
- **Log Entry**: Connection attempt recorded in system logs
- **Service Response**: Actual service may send banner information

### Closed Port Response:
- **TCP RST**: Port is closed but host is alive
- **Immediate**: RST sent immediately without service involvement
- **Host Confirmation**: Confirms host is reachable and responsive
- **No Service**: No application listening on that port

### Filtered Response:
- **No Response**: Firewall dropping packets silently
- **ICMP Unreachable**: Some firewalls send ICMP error messages
- **Timeout**: Packet lost or filtered without response
- **Uncertain Status**: Cannot determine if host is alive

## Security Implications

### For Attackers:
- **Host Discovery**: Identify live systems behind firewalls
- **Port Scanning**: Combine discovery with port enumeration
- **Service Detection**: Identify available network services
- **Firewall Testing**: Test filtering rules and policies

### For Defenders:
- **Log Monitoring**: Watch for SYN scan patterns
- **Rate Limiting**: Implement connection rate limits
- **Intrusion Detection**: Configure IDS for scan detection
- **Firewall Rules**: Block unnecessary inbound connections

### Detection Indicators:
- **High SYN Volume**: Unusual number of SYN packets
- **Port Sweeping**: SYN packets to multiple ports
- **No Full Connections**: SYN packets without completing handshake
- **Sequential Scanning**: SYN packets to sequential IP addresses

## Detection and Response

### Detection Methods:
- **IDS Signatures**: Monitor for TCP SYN scan patterns
- **Connection Analysis**: Incomplete TCP handshakes
- **Rate Analysis**: High frequency SYN packets from single source
- **Port Patterns**: SYN attempts to multiple common ports

### Response Analysis:
```
# Successful SYN Ping (Open Port)
TCP SYN to 192.168.1.1:80
Response: TCP SYN-ACK from 192.168.1.1:80
Host alive with open port 80

# Successful SYN Ping (Closed Port)  
TCP SYN to 192.168.1.1:8080
Response: TCP RST from 192.168.1.1:8080
Host alive but port 8080 closed

# Filtered/No Response
TCP SYN to 192.168.1.1:80
No response received (filtered or host down)
```

## Practical Applications

### Network Discovery:
- **Firewall Bypass**: Discover hosts when ICMP is blocked
- **Service Enumeration**: Identify available network services
- **Network Mapping**: Build topology of accessible systems
- **Asset Discovery**: Find active systems in network ranges

### Security Testing:
- **Penetration Testing**: Host discovery in hardened environments
- **Firewall Testing**: Verify filtering rule effectiveness
- **Network Assessment**: Evaluate network security posture
- **Vulnerability Scanning**: Identify potential attack surfaces

## CEH Exam Focus Points

- Understand TCP SYN ping vs. traditional ICMP ping
- Know common ports used for TCP SYN ping (80, 443, 22)
- Recognize TCP response types: SYN-ACK, RST, no response
- Understand when TCP SYN ping is more effective than ICMP
- Be familiar with Nmap -PS option and syntax
- Know security implications of TCP SYN scanning
- Understand how firewalls may handle TCP SYN packets
- Recognize detection methods for TCP SYN scans
