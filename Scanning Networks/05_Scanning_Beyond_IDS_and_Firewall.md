# Network Evasion Techniques

## 1. Packet Fragmentation

**Definition**: Splitting packets into smaller fragments to evade IDS/IPS detection.

**Key Points**:
- Fragments packets below MTU size
- IDS may not reassemble fragments properly
- **Nmap**: `nmap -f` (8-byte fragments), `nmap -ff` (16-byte fragments)
- **Custom**: `nmap --mtu 24` (custom MTU size)
- Bypasses signature-based detection
- May cause performance issues

---

## 2. Source Routing

**Definition**: Specifying the path packets take through network using IP options.

**Key Points**:
- **Loose Source Routing**: Specify some intermediate hops
- **Strict Source Routing**: Specify exact path
- **Nmap**: `nmap --ip-options "L 192.168.1.1 192.168.2.1"`
- Bypasses route-based filtering
- Most modern systems disable source routing
- Can reveal network topology

---

## 3. Source Port Manipulation

**Definition**: Using specific source ports to bypass firewall rules.

**Key Points**:
- Common bypass ports: 53 (DNS), 80 (HTTP), 443 (HTTPS)
- **Nmap**: `nmap --source-port 53` or `nmap -g 53`
- **Hping3**: `hping3 -s 53 -p 80 target`
- Firewalls often allow traffic from trusted ports
- Stateful firewalls less susceptible
- Effective against simple packet filters

---

## 4. IP Address Decoy

**Definition**: Using multiple fake source IPs to hide real scanning source.

**Key Points**:
- **Nmap**: `nmap -D RND:10` (10 random decoys)
- **Manual**: `nmap -D decoy1,decoy2,ME,decoy3 target`
- Overwhelms log analysis
- Makes source identification difficult
- Decoy IPs should be reachable
- ME = your real IP position

---

## 5. IP Address Spoofing

**Definition**: Forging source IP address in packet headers.

**Key Points**:
- **Nmap**: `nmap -S spoofed_ip target`
- **Hping3**: `hping3 -a spoofed_ip target`
- Requires raw socket access (root/admin)
- Response goes to spoofed IP
- Effective for DoS attacks
- Bypasses IP-based filtering
- Defeated by ingress filtering

---

## 6. MAC Address Spoofing

**Definition**: Changing network interface MAC address.

**Key Points**:
- **Linux**: `ifconfig eth0 hw ether 00:11:22:33:44:55`
- **Windows**: Device Manager or registry edit
- **Nmap**: `nmap --spoof-mac 0` (random MAC)
- Only affects local network segment
- Bypasses MAC-based filtering
- Useful for wireless network access
- Reset on reboot unless persistent

---

## 7. Creating Custom Packets

**Definition**: Crafting packets with specific flags, options, or data.

**Key Points**:
- **Hping3**: `hping3 -S -A -F target` (SYN+ACK+FIN flags)
- **Scapy**: Python packet crafting library
- **Nmap**: `nmap --scanflags SYNFIN`
- Bypass protocol-specific filters
- Test firewall rule parsing
- Invalid flag combinations
- Custom payload injection

---

## 8. Randomizing Host Order

**Definition**: Scanning targets in random order to avoid detection patterns.

**Key Points**:
- **Nmap**: `nmap --randomize-hosts target_range`
- Default behavior in newer Nmap versions
- Prevents sequential scan detection
- Reduces IDS pattern recognition
- Distributes scan load
- Makes correlation difficult

---

## 9. Sending Bad Checksum

**Definition**: Using incorrect checksums to evade IDS inspection.

**Key Points**:
- **Nmap**: `nmap --badsum target`
- **Hping3**: `hping3 --badcksum target`
- IDS may ignore packets with bad checksums
- Target host discards invalid packets
- Tests IDS checksum validation
- No response expected from target
- Pure evasion technique

---

## 10. Proxy Servers

**Definition**: Using intermediate servers to hide source identity.

**Key Points**:
- **HTTP Proxy**: Web traffic routing
- **SOCKS Proxy**: All TCP traffic
- **Nmap**: `nmap --proxies http://proxy:8080 target`
- **ProxyChains**: Chain multiple proxies
- Anonymizes source IP
- May introduce latency
- Some proxies log traffic

**Common Proxy Types**:
- Transparent (no anonymity)
- Anonymous (hides IP, reveals proxy use)
- Elite (complete anonymity)

---

## 11. Anonymizers

**Definition**: Services/tools that hide user identity and location.

**Key Points**:
- **Tor Network**: Onion routing through multiple nodes
- **VPN Services**: Encrypted tunnels to exit points
- **Anonymous Proxies**: Identity-hiding proxy services
- **Mix Networks**: Message routing through multiple servers

**Tor Usage**:
- Download Tor browser or use command line
- Multiple encryption layers
- Exit node sees final traffic
- Slow but highly anonymous

**VPN Considerations**:
- Choose no-log providers
- Multiple server locations
- Kill switch functionality
- DNS leak protection

---

## CEH Exam Key Points Summary

**Most Important Commands**:
- `nmap -f` - Fragment packets
- `nmap -D RND:10` - Use random decoys  
- `nmap -S spoofed_ip` - Spoof source IP
- `nmap --source-port 53` - Use specific source port
- `nmap --randomize-hosts` - Random scan order

**Detection Evasion Strategy**:
1. Use multiple techniques together
2. Slow scan timing (`-T1`, `-T2`)
3. Fragment packets and use decoys
4. Randomize scan order and timing
5. Use trusted source ports

**Limitations to Remember**:
- Stateful firewalls are harder to evade
- Modern IDS systems reassemble fragments
- Ingress filtering blocks spoofed IPs
- Some techniques require root/admin privileges
- May cause legitimate traffic issues
