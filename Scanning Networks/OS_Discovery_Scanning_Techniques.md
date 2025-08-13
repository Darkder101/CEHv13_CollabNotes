# OS Discovery Scanning Techniques - CEH Quick Notes

## 1. Active OS Fingerprinting

**Definition**: Sending packets to a target and analyzing the responses to identify the operating system.

**Key Points**:
- **Nmap**: `nmap -O target_ip` - Primary OS detection command
- **Enhanced**: `nmap -O --osscan-guess target_ip` - Aggressive OS guessing
- **Timing**: `nmap -O -T4 target_ip` - Faster OS detection
- High accuracy but easily detected by IDS/IPS
- Requires open/closed ports for analysis
- Uses TCP/IP stack fingerprinting

---

## 2. Passive OS Fingerprinting

**Definition**: Examining traffic on the network to determine the operating system using sniffing techniques.

**Key Points**:
- **p0f**: Primary passive fingerprinting tool
- **Wireshark**: Analyze captured packets for OS indicators
- Stealthier and usually goes undetected by IDS
- Less accurate than active fingerprinting
- No packets sent to target
- Analyzes existing network traffic

---

## 3. TCP/IP Stack Fingerprinting

**Definition**: Analyzing TCP/IP implementation differences between operating systems.

**Key Points**:
- **Initial Window Size**: Different OS use different values
- **TTL Values**: Windows (128), Linux (64), Cisco (255)
- **TCP Options**: MSS, Window Scaling, Timestamp
- **IP Flags**: Don't Fragment bit handling
- **ICMP Responses**: Error message formats vary
- **TCP Sequence**: Sequence number generation patterns

**Common TTL Values**:
- Windows: 128
- Linux/Unix: 64
- Cisco: 255
- FreeBSD: 64
- Solaris: 255

---

## 4. Banner Grabbing

**Definition**: Collecting service banners that reveal OS and application information.

**Key Points**:
- **Telnet**: `telnet target_ip port`
- **Netcat**: `nc -nv target_ip port`
- **Nmap**: `nmap -sV target_ip` - Service version detection
- **SSH**: `ssh target_ip` (shows SSH banner)
- **HTTP**: `curl -I http://target_ip` (headers reveal OS)
- Easy to implement but limited information

**Common Banner Services**:
- SSH (port 22)
- Telnet (port 23)
- SMTP (port 25)
- HTTP (port 80)
- POP3 (port 110)
- HTTPS (port 443)

---

## 5. ICMP-Based OS Detection

**Definition**: Using ICMP message analysis to identify operating systems.

**Key Points**:
- **ICMP Echo**: Different response patterns
- **ICMP Timestamp**: Implementation variations
- **ICMP Address Mask**: Response behavior differences
- **Error Messages**: ICMP unreachable format variations
- **Nmap**: Uses ICMP in OS detection scan
- Limited by firewalls blocking ICMP

---

## 6. Protocol-Specific Fingerprinting

**Definition**: Analyzing protocol implementation differences for OS identification.

**Key Points**:
- **TCP Window Size**: Operating system defaults
- **TCP Options Order**: Different OS arrange differently
- **UDP Responses**: Port unreachable message formats
- **SNMP**: `snmpget` for system information
- **NetBIOS**: `nbtscan` for Windows systems
- **Timing Analysis**: Response time patterns

---

## 7. Service Version Detection

**Definition**: Identifying specific service versions that indicate underlying OS.

**Key Points**:
- **Nmap**: `nmap -sV -O target_ip` - Combined version and OS
- **Service Probes**: Send specific requests to services
- **Application Banners**: Reveal OS in service responses
- **Default Configurations**: OS-specific service setups
- **Port Combinations**: Typical port usage patterns
- More accurate than simple banner grabbing

---

## 8. Behavioral Analysis

**Definition**: Observing system behavior patterns to determine OS type.

**Key Points**:
- **Response Timing**: Different OS response speeds
- **Connection Handling**: TCP connection behavior
- **Resource Limits**: Maximum connection handling
- **Error Responses**: How systems handle invalid requests
- **Fragmentation**: IP fragmentation handling differences
- Requires multiple test packets

---

## 9. Packet Timing Analysis

**Definition**: Using response timing patterns to identify operating systems.

**Key Points**:
- **Nmap Timing**: `nmap -O --osscan-limit target_ip`
- **Response Delays**: OS-specific processing times
- **TCP Retransmission**: Different timeout values
- **Jitter Analysis**: Consistency in response timing
- **Load Response**: How systems handle multiple requests
- Network conditions affect accuracy

---

## 10. Registry and File System Fingerprinting

**Definition**: Identifying OS through exposed file systems or registry information.

**Key Points**:
- **SMB Shares**: `smbclient -L target_ip` - Windows systems
- **NFS Exports**: `showmount -e target_ip` - Unix/Linux
- **Web Directories**: Default web server paths
- **FTP Anonymous**: Default directory structures
- **SNMP MIB**: System information via SNMP
- Requires service access

---

## CEH Exam Key Commands Summary

**Primary Commands**:
- `nmap -O target_ip` - Active OS fingerprinting
- `nmap -sV target_ip` - Service version detection  
- `nmap -O -sV target_ip` - Combined OS and service detection
- `p0f -i interface` - Passive OS fingerprinting
- `telnet target_ip port` - Manual banner grabbing
- `nc -nv target_ip port` - Netcat banner grabbing

**Important Nmap OS Options**:
- `-O` - Enable OS detection
- `--osscan-limit` - Limit OS detection to promising targets
- `--osscan-guess` - Guess OS more aggressively
- `--max-os-tries` - Set maximum OS detection tries

**TTL Values to Remember**:
- Windows: 128
- Linux/Unix: 64
- Cisco: 255

**Detection Methods**:
1. **Active**: Send packets, analyze responses (high accuracy, detectable)
2. **Passive**: Analyze existing traffic (stealthy, lower accuracy)
3. **Banner Grabbing**: Read service banners (simple, limited info)

**Key Differences**:
- **TCP Window Sizes**: OS-specific defaults
- **ICMP Responses**: Implementation variations  
- **Service Banners**: Application version strings
- **Protocol Behavior**: Stack implementation differences

**Evasion Considerations**:
- Use passive techniques when stealth required
- Combine multiple methods for accuracy
- Be aware of IDS/IPS detection capabilities
- Consider timing attacks for better stealth
