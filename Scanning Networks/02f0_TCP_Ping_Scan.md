# TCP Ping Scan

## Definition

TCP Ping Scan is a host discovery technique that uses TCP (Transmission Control Protocol) packets to identify live hosts on a network. This method sends TCP packets to specific ports on target systems and analyzes the responses to determine host availability. TCP ping scans are highly effective for firewall evasion since TCP traffic is commonly allowed through firewalls, and they provide dual functionality by discovering both host status and port availability simultaneously.

## How TCP Ping Scan Works

### Basic Process:
1. **Source Host** sends TCP packet (SYN, ACK, or other flags) to target port
2. **Target Host** receives TCP packet and processes based on port status
3. **Target Host** responds according to port state and TCP implementation
4. **Source Host** analyzes response to determine host and port status
5. **Source Host** may complete or abort connection based on scan type

### Packet Structure:
- **IP Header**: Source and destination IP addresses, protocol field (TCP=6)
- **TCP Header**: Source/destination ports, sequence numbers, flags, window size
- **TCP Flags**: SYN, ACK, RST, FIN combinations for different scan types
- **Response**: SYN-ACK, RST, or ICMP error messages

## TCP Flag Combinations

| Flags | Name | Purpose |
|-------|------|---------|
| SYN | Synchronize | Initiate connection (TCP SYN Ping) |
| ACK | Acknowledge | Acknowledge receipt (TCP ACK Ping) |
| SYN+ACK | Synchronize-Acknowledge | Connection accepted response |
| RST | Reset | Connection refused/port closed |
| FIN | Finish | Connection termination |

## Tools and Commands

### Nmap TCP Ping Scans
```bash
# TCP SYN ping (default TCP ping)
nmap -sn -PS22,80,443 192.168.1.0/24

# TCP ACK ping
nmap -sn -PA22,80,443 192.168.1.0/24

# TCP ping to common ports
nmap -sn -PS21,22,23,25,53,80,110,443,993,995 192.168.1.1

# Combined TCP ping methods
nmap -sn -PS80 -PA443 192.168.1.0/24
```

### Hping3 TCP Packets
```bash
# TCP SYN ping
hping3 -S -p 80 -c 3 192.168.1.1

# TCP ACK ping
hping3 -A -p 443 -c 3 192.168.1.1

# TCP with custom flags
hping3 -F -P -U -p 22 192.168.1.1

# TCP ping with data
hping3 -S -p 80 -d 32 192.168.1.1
```

### Netcat TCP Testing
```bash
# TCP connection test
nc -zv 192.168.1.1 22

# TCP port range test
nc -zv 192.168.1.1 20-25

# TCP with timeout
timeout 3 nc -zv 192.168.1.1 80
```

## TCP Response Patterns

### SYN Ping Responses:
- **SYN-ACK**: Port open, host alive, service accepting connections
- **RST**: Port closed, host alive, service not running
- **ICMP Unreachable**: Network/host filtering or unreachable
- **No Response**: Filtered by firewall or host down

### ACK Ping Responses:
- **RST**: Host alive (normal response to unsolicited ACK)
- **No Response**: Filtered, host down, or strict firewall
- **ICMP Unreachable**: Network filtering or routing issues

## Common TCP Ping Ports

| Port | Service | Rationale |
|------|---------|-----------|
| 22 | SSH | Commonly open on Unix/Linux systems |
| 80 | HTTP | Web servers, very common |
| 443 | HTTPS | Secure web, increasingly common |
| 25 | SMTP | Email servers |
| 53 | DNS | Domain name servers |
| 21 | FTP | File transfer services |
| 23 | Telnet | Remote access (legacy) |
| 110 | POP3 | Email retrieval |
| 993 | IMAPS | Secure email |
| 3389 | RDP | Windows Remote Desktop |

## Advantages

- **Firewall Traversal**: TCP traffic commonly allowed through firewalls
- **Dual Purpose**: Discovers hosts and identifies open ports simultaneously
- **High Reliability**: TCP responses are consistent and predictable
- **Stealth Capability**: Can appear as legitimate connection attempts
- **Protocol Support**: Works across NAT and various network configurations
- **Service Identification**: Reveals running services and their availability

## Limitations

- **Port Dependency**: Effectiveness depends on target having open TCP ports
- **Firewall Detection**: Advanced firewalls may detect scanning patterns
- **Service Dependency**: Requires services to be running on target ports
- **Connection Overhead**: May create logs in target service applications
- **Rate Limiting**: Some systems implement connection rate limiting
- **IDS Signatures**: May trigger intrusion detection systems

## System Response Behaviors

### Web Services (Ports 80/443):
- **Active Servers**: Send SYN-ACK for connection establishment
- **Load Balancers**: May respond even if backend servers are down
- **Reverse Proxies**: Respond on behalf of application servers
- **CDN Endpoints**: Geographic distribution affects response times

### SSH Services (Port 22):
- **OpenSSH**: Sends SYN-ACK and waits for SSH handshake
- **Secured SSH**: May implement connection limiting or filtering
- **Key-based Auth**: Service responds regardless of auth method
- **Fail2ban Protection**: May block after repeated connections

### Email Services (Ports 25/110/143):
- **Mail Servers**: Accept connections for SMTP/POP3/IMAP protocols
- **Relay Restrictions**: May accept but restrict based on source
- **Authentication Required**: Service available but requires credentials
- **Anti-spam Measures**: May implement connection delays

### Database Services:
- **MySQL (3306)**: Accepts connections but requires authentication
- **PostgreSQL (5432)**: Similar connection acceptance pattern
- **SQL Server (1433)**: Windows-based database connectivity
- **Oracle (1521)**: Enterprise database connection handling

## Security Implications

### Information Disclosure:
- **Service Enumeration**: Reveals running services and versions
- **Network Architecture**: Shows open communication paths
- **Operating System Hints**: TCP implementation differences
- **Security Posture**: Indicates firewall and filtering effectiveness

### For Defenders:
- **Connection Monitoring**: Track unusual connection patterns
- **Service Hardening**: Minimize unnecessary service exposure
- **Firewall Tuning**: Implement appropriate TCP filtering
- **Rate Limiting**: Control connection attempt rates

### Attack Vectors:
- **Port Scanning**: Identify potential attack targets
- **Service Exploitation**: Target discovered services for vulnerabilities
- **Denial of Service**: Overwhelm services with connection requests
- **Reconnaissance**: Gather system and network intelligence

## Detection and Response

### Detection Methods:
- **Connection Logs**: Monitor application and system connection logs
- **Network IDS**: Signatures for TCP scanning patterns
- **Firewall Logs**: Track blocked and allowed TCP connections
- **Behavioral Analysis**: Identify unusual connection patterns

### Response Analysis:
```
# Open Port Response (SYN Ping)
TCP SYN to 192.168.1.1:80
Response: SYN-ACK from port 80
Host alive, HTTP service running

# Closed Port Response (SYN Ping)
TCP SYN to 192.168.1.1:8080
Response: RST from port 8080
Host alive, no service on port 8080

# Filtered Response
TCP SYN to 192.168.1.1:22
No response received
Port filtered or host down

# ACK Ping Response
TCP ACK to 192.168.1.1:443
Response: RST packet
Host alive (normal ACK response)
```

## Practical Applications

### Network Discovery:
- **Host Enumeration**: Identify active systems via TCP responses
- **Service Mapping**: Catalog available TCP services
- **Network Topology**: Understand communication paths and filtering
- **Asset Management**: Maintain inventory of networked services

### Penetration Testing:
- **Target Identification**: Locate systems with accessible services
- **Attack Surface Mapping**: Identify potential entry points
- **Firewall Assessment**: Test TCP filtering effectiveness
- **Reconnaissance Phase**: Gather intelligence on network services

### System Administration:
- **Service Monitoring**: Verify TCP service availability
- **Network Troubleshooting**: Test connectivity and filtering
- **Configuration Validation**: Confirm service bindings and access
- **Performance Assessment**: Measure connection response times

## CEH Exam Focus Points

- Understand TCP is connection-oriented and stateful protocol
- Know SYN-ACK response indicates open port and alive host
- Recognize RST response means host alive but port closed
- Understand Nmap -PS flag for SYN ping, -PA for ACK ping
- Know common ports used for TCP ping (22, 80, 443, 25)
- Recognize TCP ping provides both host discovery and port status
- Understand TCP ping effectiveness for firewall evasion
---
