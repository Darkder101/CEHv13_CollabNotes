# Port and Service Discovery Techniques - CEH Quick Notes

## 1. TCP Connect Scan

**Definition**: Full TCP three-way handshake to determine port status.

**Key Points**:
- **Nmap**: `nmap -sT target_ip` - TCP Connect scan
- Completes full TCP connection (SYN → SYN-ACK → ACK)
- Most accurate but easily logged
- Default when no raw socket privileges
- Slow due to full connection establishment
- **Open**: Connection established, **Closed**: Connection refused

---

## 2. TCP SYN Scan (Half-Open)

**Definition**: Send SYN packets without completing handshake.

**Key Points**:
- **Nmap**: `nmap -sS target_ip` - Default scan type
- **Stealth**: Doesn't complete connection (SYN → SYN-ACK → RST)
- Requires raw socket access (root/admin)
- Faster than TCP Connect
- Less likely to be logged by applications
- **Open**: SYN-ACK received, **Closed**: RST received

---

## 3. TCP FIN Scan

**Definition**: Send FIN packets to closed ports expecting RST response.

**Key Points**:
- **Nmap**: `nmap -sF target_ip` - FIN scan
- **Stealth**: Bypasses simple firewalls
- **Open|Filtered**: No response, **Closed**: RST response
- Effective against stateless firewalls
- Windows systems may not respond correctly
- Part of TCP NULL, FIN, Xmas scan family

---

## 4. TCP Xmas Scan

**Definition**: Send packets with FIN, PSH, and URG flags set.

**Key Points**:
- **Nmap**: `nmap -sX target_ip` - Xmas scan
- **Flags**: FIN + PSH + URG (packet "lit up like Christmas tree")
- **Open|Filtered**: No response, **Closed**: RST response
- Bypasses simple packet filters
- Named for multiple flags being set
- May not work on Windows systems

---

## 5. TCP NULL Scan

**Definition**: Send TCP packets with no flags set.

**Key Points**:
- **Nmap**: `nmap -sN target_ip` - NULL scan
- **No Flags**: All TCP flags turned off
- **Open|Filtered**: No response, **Closed**: RST response
- Stealthier than normal scans
- Firewall evasion technique
- RFC compliance varies by OS

---

## 6. TCP ACK Scan

**Definition**: Send ACK packets to determine firewall rules and port filtering.

**Key Points**:
- **Nmap**: `nmap -sA target_ip` - ACK scan
- **Purpose**: Firewall rule mapping, not port state
- **Unfiltered**: RST response, **Filtered**: No response/ICMP unreachable
- Tests stateful firewall behavior
- Cannot determine if ports are open
- Useful for firewall analysis

---

## 7. UDP Scan

**Definition**: Send UDP packets to identify open UDP services.

**Key Points**:
- **Nmap**: `nmap -sU target_ip` - UDP scan
- **Open**: Service response or no response
- **Closed**: ICMP Port Unreachable (Type 3, Code 3)
- Slower than TCP scans
- Often rate-limited by systems
- **Common UDP Ports**: 53 (DNS), 161 (SNMP), 69 (TFTP)

---

## 8. Service Version Detection

**Definition**: Identify specific services and versions running on open ports.

**Key Points**:
- **Nmap**: `nmap -sV target_ip` - Service version detection
- **Intensity**: `nmap -sV --version-intensity 0-9`
- **All Ports**: `nmap -sV --version-all target_ip`
- Sends probes to determine service type
- More accurate than banner grabbing
- May trigger IDS due to probe activity

---

## 9. Aggressive Scan

**Definition**: Combines OS detection, service version, script scanning, and traceroute.

**Key Points**:
- **Nmap**: `nmap -A target_ip` - Aggressive scan
- **Equivalent**: `-O -sV -sC --traceroute`
- Comprehensive but noisy
- Takes longer to complete
- High detection probability
- Good for thorough reconnaissance

---

## 10. Script Scanning (NSE)

**Definition**: Use Nmap Scripting Engine for advanced service detection.

**Key Points**:
- **Nmap**: `nmap -sC target_ip` - Default scripts
- **Specific**: `nmap --script script_name target_ip`
- **Categories**: auth, broadcast, brute, discovery, exploit, intrusive, safe, vuln
- **Examples**: `--script http-title`, `--script smb-enum-shares`
- Automated vulnerability detection
- **Script Location**: `/usr/share/nmap/scripts/`

---

## 11. Banner Grabbing

**Definition**: Retrieve service banners to identify applications and versions.

**Key Points**:
- **Telnet**: `telnet target_ip port`
- **Netcat**: `nc -nv target_ip port`
- **HTTP**: `curl -I http://target_ip`
- **Manual**: Connect and read service response
- Simple but effective
- Limited to banner-displaying services

---

## 12. Port Range and Timing Options

**Definition**: Specify port ranges and scan timing for optimization.

**Key Points**:
- **All Ports**: `nmap -p- target_ip` (1-65535)
- **Specific**: `nmap -p 80,443,22 target_ip`
- **Range**: `nmap -p 1-1000 target_ip`
- **Top Ports**: `nmap --top-ports 100 target_ip`
- **Timing**: `-T0` (paranoid) to `-T5` (insane)
- **Fast**: `nmap -F target_ip` (top 100 ports)

---

## 13. Idle Scan (Zombie)

**Definition**: Use a third-party host to perform stealthy port scanning.

**Key Points**:
- **Nmap**: `nmap -sI zombie_ip target_ip`
- **Requirements**: Idle host with predictable IP ID sequence
- Completely anonymous scanning
- Very slow but extremely stealthy
- Difficult to configure and execute
- **Detection**: Find idle hosts with `nmap -O target`

---

## 14. Window Scan

**Definition**: Examine TCP window size in RST packets to determine port state.

**Key Points**:
- **Nmap**: `nmap -sW target_ip` - Window scan
- **Principle**: Open ports may have different window sizes
- **Limited**: Only works on certain systems
- **Open**: Positive window size, **Closed**: Zero window
- Less reliable than other methods
- System-dependent behavior

---

## 15. Maimon Scan

**Definition**: Send FIN/ACK packets expecting different responses from open/closed ports.

**Key Points**:
- **Nmap**: `nmap -sM target_ip` - Maimon scan
- **Flags**: FIN + ACK
- **BSD Systems**: Drop packets to open ports
- **Other Systems**: RST for both open and closed
- Named after Uriel Maimon
- Limited effectiveness on modern systems

---

## CEH Exam Key Commands Summary

**Essential Nmap Scans**:
- `nmap -sS target_ip` - SYN scan (default, stealth)
- `nmap -sT target_ip` - TCP Connect scan (full connection)
- `nmap -sU target_ip` - UDP scan
- `nmap -sV target_ip` - Service version detection
- `nmap -A target_ip` - Aggressive scan (OS + services + scripts)

**Stealth Scans**:
- `nmap -sF target_ip` - FIN scan
- `nmap -sN target_ip` - NULL scan
- `nmap -sX target_ip` - Xmas scan
- `nmap -sI zombie target_ip` - Idle/Zombie scan

**Port Specifications**:
- `nmap -p- target_ip` - All 65535 ports
- `nmap -p 1-1000 target_ip` - Port range
- `nmap --top-ports 100 target_ip` - Top 100 ports
- `nmap -F target_ip` - Fast scan (top 100)

**Timing Templates**:
- `-T0` Paranoid (very slow, IDS evasion)
- `-T1` Sneaky (slow, IDS evasion)
- `-T2` Polite (slower, less bandwidth)
- `-T3` Normal (default timing)
- `-T4` Aggressive (faster, assumes good network)
- `-T5` Insane (very fast, may sacrifice accuracy)

**Port States**:
- **Open**: Service accepting connections
- **Closed**: Port accessible but no service
- **Filtered**: Firewall/filter blocking access
- **Open|Filtered**: Cannot determine (UDP/stealth scans)
- **Closed|Filtered**: Cannot determine if closed or filtered
- **Unfiltered**: Port accessible but state unknown

**UDP Scan Considerations**:
- Much slower than TCP scans
- Often rate-limited by target systems
- ICMP responses indicate closed ports
- No response may mean open or filtered

**Service Detection Tips**:
- Combine `-sV` with other scans
- Use `--version-intensity` for thoroughness
- NSE scripts provide additional service info
- Banner grabbing for manual verification
