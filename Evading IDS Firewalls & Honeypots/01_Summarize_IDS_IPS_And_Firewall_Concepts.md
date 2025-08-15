## 01 - Summarize IDS, IPS and Firewall Concepts

### A. Intrusion Detection System (IDS)

**Definition:** An Intrusion Detection System is a security tool that monitors network traffic, system activities, and files for malicious activities or policy violations.

**Key Characteristics:**
- **Passive monitoring system** - detects and alerts but doesn't block
- Operates in **promiscuous mode** to capture all network traffic
- Analyzes traffic patterns and compares against known attack signatures
- Generates alerts when suspicious activities are detected
- Cannot stop attacks in real-time (detection only)

**Primary Functions:**
- Monitor network traffic continuously
- Identify suspicious patterns and behaviors
- Generate alerts and logs for security incidents
- Provide forensic analysis capabilities

### B. Intrusion Prevention System (IPS)

**Definition:** An Intrusion Prevention System is an active security device that not only detects malicious activities but also takes immediate action to prevent or block them.

**Key Characteristics:**
- **Active protection system** - detects, alerts, and blocks
- Operates **inline** with network traffic flow
- Can automatically respond to threats in real-time
- May cause network latency due to inline processing
- Combines detection and prevention capabilities

**Primary Functions:**
- Real-time traffic analysis and blocking
- Automatic threat response and mitigation
- Integration with firewall policies
- Advanced threat detection using behavioral analysis

### C. How IDS Detect Intrusion

**1. Signature-Based Detection:**
- Compares network traffic against database of known attack patterns
- Uses predefined rules and signatures
- Effective against known attacks
- Limited against zero-day exploits

**2. Anomaly-Based Detection:**
- Establishes baseline of normal network behavior
- Identifies deviations from established patterns
- Can detect unknown attacks
- Higher false positive rates

**3. Protocol Analysis:**
- Monitors protocol-specific traffic
- Identifies protocol violations and anomalies
- Analyzes application layer protocols

**4. Stateful Inspection:**
- Tracks connection states and contexts
- Monitors entire communication sessions
- Validates protocol state transitions

### D. General Indication of Intrusion

**Network-Level Indicators:**
- Unusual network traffic patterns
- Unexpected protocols on non-standard ports
- High volume of connections to/from single host
- Traffic during non-business hours
- Bandwidth consumption anomalies

**System-Level Indicators:**
- Multiple failed login attempts
- Privilege escalation activities
- Unauthorized file access or modifications
- Unusual process executions
- System performance degradation

**Application-Level Indicators:**
- SQL injection attempts
- Cross-site scripting (XSS) attacks
- Buffer overflow attempts
- Unauthorized data access patterns
- Session hijacking indicators

### E. Types of Intrusion Detection System

#### Based on Deployment Location:

**1. Network-Based IDS (NIDS):**
- Monitors network segments and subnets
- Analyzes network packets in real-time
- Positioned at strategic network points
- Examples: Snort, Suricata

**2. Host-Based IDS (HIDS):**
- Monitors individual host systems
- Analyzes system logs, file integrity, registry changes
- Installed on critical servers and workstations
- Examples: OSSEC, Samhain

**3. Wireless IDS (WIDS):**
- Specialized for wireless network monitoring
- Detects rogue access points and wireless attacks
- Monitors 802.11 wireless protocols
- Examples: AirDefense, AirMagnet

#### Based on Detection Method:

**1. Signature-Based IDS:**
- Pattern matching against known attack signatures
- Low false positive rates
- Cannot detect unknown attacks
- Requires regular signature updates

**2. Anomaly-Based IDS:**
- Statistical analysis of normal vs. abnormal behavior
- Can detect zero-day attacks
- Higher false positive rates
- Requires learning period for baseline establishment

**3. Hybrid IDS:**
- Combines signature-based and anomaly-based detection
- Balances accuracy and detection capabilities
- More comprehensive threat detection
- Higher resource requirements

### F. Types of IDS Alerts

**1. True Positive:**
- Legitimate attack correctly identified
- Appropriate alert generated
- Desired IDS behavior

**2. False Positive:**
- Normal activity incorrectly flagged as malicious
- Unnecessary alert generated
- Can lead to alert fatigue

**3. True Negative:**
- Normal activity correctly identified as benign
- No alert generated (correct behavior)
- Ideal for normal operations

**4. False Negative:**
- Actual attack not detected by IDS
- No alert generated when one should be
- Most dangerous scenario for security

**Alert Severity Levels:**
- **High:** Critical security incidents requiring immediate attention
- **Medium:** Suspicious activities requiring investigation
- **Low:** Minor policy violations or informational events
- **Informational:** Normal activities logged for audit purposes

### G. Firewall

**Definition:** A firewall is a network security device that monitors and controls incoming and outgoing network traffic based on predetermined security rules and policies.

**Core Purpose:**
- Create security barrier between trusted and untrusted networks
- Filter traffic based on rules and policies
- Prevent unauthorized access to network resources
- Log and monitor network communications

**Key Functions:**
- **Packet Filtering:** Examine packet headers (IP, port, protocol)
- **Stateful Inspection:** Track connection states and contexts
- **Application Layer Filtering:** Deep packet inspection of application data
- **Network Address Translation (NAT):** Hide internal network structure
- **Virtual Private Network (VPN):** Secure remote connections

### H. Firewall Architecture

**1. Screened Host Architecture:**
- Single firewall device protecting internal network
- All traffic must pass through firewall
- Simple and cost-effective solution
- Single point of failure

**2. Screened Subnet Architecture:**
- Multiple firewalls creating layered security
- DMZ between internal and external networks
- Enhanced security through defense in depth
- More complex to manage

**3. Dual-Homed Host:**
- Computer with two network interfaces
- Acts as gateway between networks
- Software-based firewall solution
- Limited scalability

### I. Demilitarized Zone (DMZ)

**Definition:** A DMZ is a perimeter network that sits between an organization's internal network and an external network (usually the Internet).

**Purpose:**
- Isolate public-facing services from internal network
- Provide controlled access to external users
- Add extra layer of security protection
- Host services that need Internet access

**Common DMZ Services:**
- Web servers (HTTP/HTTPS)
- Mail servers (SMTP/POP3/IMAP)
- DNS servers
- FTP servers
- Application servers
- Database servers (with restricted access)

**Security Benefits:**
- Limits exposure of internal network
- Contains potential security breaches
- Provides monitored zone for public services
- Enables granular access control policies

### J. Types of Firewall

#### i. Based on Configuration

**1. Software Firewall:**
- Installed on individual computers or servers
- Host-based protection
- Examples: Windows Defender Firewall, iptables
- **Advantages:** Cost-effective, granular control per host
- **Disadvantages:** Resource consumption, limited network-wide protection

**2. Hardware Firewall:**
- Dedicated physical devices
- Network-based protection
- Examples: Cisco ASA, Fortinet FortiGate, Palo Alto Networks
- **Advantages:** High performance, centralized management, network-wide protection
- **Disadvantages:** Higher cost, single point of failure

**3. Cloud Firewall:**
- Software-defined security in cloud environments
- Examples: AWS Security Groups, Azure NSG, Google Cloud Firewall
- **Advantages:** Scalability, integration with cloud services
- **Disadvantages:** Dependency on cloud provider, potential latency

#### ii. Based on Mechanism

**1. Packet Filtering Firewall:**
- **Layer:** Network Layer (Layer 3) and Transport Layer (Layer 4)
- **Mechanism:** Examines packet headers (source/destination IP, ports, protocols)
- **Advantages:** Fast processing, low resource usage, simple rules
- **Disadvantages:** No application awareness, vulnerable to IP spoofing, limited logging

**2. Stateful Inspection Firewall:**
- **Layer:** Network Layer (Layer 3) and Transport Layer (Layer 4)
- **Mechanism:** Tracks connection states and maintains state table
- **Advantages:** Context-aware filtering, better security than packet filtering
- **Disadvantages:** Higher resource usage, vulnerable to state table attacks

**3. Application Layer Firewall (Proxy Firewall):**
- **Layer:** Application Layer (Layer 7)
- **Mechanism:** Acts as intermediary for client-server communications
- **Advantages:** Deep packet inspection, application-aware filtering, enhanced security
- **Disadvantages:** Higher latency, resource intensive, scalability limitations

**4. Next-Generation Firewall (NGFW):**
- **Layer:** All layers (Layer 2-7)
- **Mechanism:** Combines traditional firewall with advanced features
- **Features:** IPS integration, application awareness, user identity, SSL inspection
- **Advantages:** Comprehensive security, advanced threat detection
- **Disadvantages:** Higher cost, complexity, resource requirements

**5. Circuit-Level Gateway:**
- **Layer:** Session Layer (Layer 5)
- **Mechanism:** Monitors TCP handshake and session establishment
- **Advantages:** Fast processing, hides internal network details
- **Disadvantages:** No application layer inspection, limited security features

---

**Note:** This summary provides foundational knowledge for understanding IDS, IPS, and Firewall concepts essential for CEH v13 exam preparation. Each topic will be expanded with specific evasion techniques in separate modules.
