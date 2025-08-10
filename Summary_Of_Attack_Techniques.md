# 🎯 CEH v13 Complete Attack Techniques & Tool Cross-Reference
---

## 1️⃣ Reconnaissance & Footprinting Attacks

### **Passive Reconnaissance** – No direct target contact
- **Google Dorking (Advanced Search Operators)**  
  - `site:target.com filetype:pdf`  
  - `inurl:admin.php site:target.com`  
  - `cache:target.com`  
  - `related:target.com`  
- **Social Media Intelligence (SOCMINT)**  
  - LinkedIn employee profiling  
  - Facebook/Twitter metadata analysis  
  - Instagram geolocation extraction  
  - GitHub code repository analysis  
- **OSINT Framework Exploitation**  
  - Shodan.io IoT device discovery  
  - Censys.io certificate transparency mining  
  - Archive.org historical data mining  
  - Maltego relationship mapping  
- **DNS Intelligence Gathering**  
  - DNS enumeration (dig, dnsrecon)  
  - Certificate transparency log analysis  
  - Subdomain takeover identification  
- **Metadata Exploitation**  
  - EXIF data extraction from images  
  - Document metadata analysis  
  - Email header analysis  
  - Website source code comments mining  

### **Active Reconnaissance** – Direct target interaction
- **Network Discovery**  
  - Ping sweeps and host enumeration  
  - Nmap scanning with various techniques  
  - Banner grabbing and service identification  
  - Traceroute analysis  
- **DNS Interrogation**  
  - DNS zone transfer attempts (AXFR)  
  - DNS cache snooping  
  - DNS amplification reconnaissance  
- **Email System Probing**  
  - SMTP VRFY/EXPN commands  
  - Email header analysis  
  - Mail server fingerprinting  
- **SNMP Enumeration**  
  - SNMP community string attacks  
  - MIB walking and system information extraction  

---

## 2️⃣ Scanning & Enumeration Attacks

### **Network Scanning Techniques**
- **Port Scanning Methodologies**  
  - TCP Connect scan (-sT)  
  - SYN Stealth scan (-sS)  
  - FIN scan (-sF)  
  - NULL scan (-sN)  
  - XMAS scan (-sX)  
  - ACK scan (-sA)  
  - UDP scan (-sU)  
  - SCTP INIT scan (-sY)  
  - Idle scan (-sI) using zombie hosts  

### **Service Enumeration**
- **SMB/NetBIOS Enumeration**  
  - enum4linux comprehensive scanning  
  - smbclient share enumeration  
  - nbtstat NetBIOS information gathering  
  - rpcclient null session attacks  
- **SNMP Enumeration**  
  - snmpwalk MIB tree traversal  
  - SNMP community string brute forcing  
  - System information extraction  
- **Database Enumeration**  
  - MySQL enumeration (port 3306)  
  - MSSQL enumeration (port 1433)  
  - Oracle enumeration (port 1521)  
  - MongoDB enumeration (port 27017)  
- **Web Service Enumeration**  
  - HTTP methods enumeration  
  - WebDAV scanning  
  - SSL/TLS configuration analysis  
- **Directory Services**  
  - LDAP enumeration and query injection  
  - Active Directory reconnaissance  
  - Kerberos enumeration  

### **Vulnerability Scanning**
- **Automated Vulnerability Assessment**  
  - Nessus comprehensive scanning  
  - OpenVAS open-source scanning  
  - Qualys cloud-based scanning  
  - Rapid7 Nexpose enterprise scanning  
- **Web Application Scanning**  
  - Nikto web server scanning  
  - OWASP ZAP automated scanning  
  - Acunetix web vulnerability scanning  

---

## 3️⃣ System Hacking & Exploitation

### **Password Attacks**
- **Online Password Attacks**  
  - Brute force attacks (Hydra, Medusa)  
  - Dictionary attacks with custom wordlists  
  - Credential stuffing attacks  
  - Password spraying techniques  
- **Offline Password Attacks**  
  - Rainbow table attacks  
  - Hybrid attacks (John + rules)  
  - GPU-accelerated cracking (Hashcat)  
  - Distributed password cracking  
- **Hash-based Attacks**  
  - NTLM hash cracking  
  - MD5/SHA hash collision attacks  
  - Pass-the-hash attacks  
  - Golden ticket attacks (Kerberos)  

### **Privilege Escalation**
- **Windows Privilege Escalation**  
  - Token impersonation  
  - UAC bypass techniques  
  - Service exploitation (unquoted paths)  
  - Registry manipulation  
  - DLL hijacking  
- **Linux Privilege Escalation**  
  - SUID/SGID binary exploitation  
  - Kernel exploits  
  - Cron job manipulation  
  - Docker escape techniques  
  - Sudo misconfigurations  

### **Buffer Overflow Attacks**
- **Stack-based Buffer Overflows**  
  - EIP overwrite techniques  
  - Return address manipulation  
  - NOP sled construction  
- **Heap-based Buffer Overflows**  
  - Heap spraying techniques  
  - Use-after-free exploitation  
- **Modern Bypass Techniques**  
  - ASLR bypass methods  
  - DEP/NX bit circumvention  
  - ROP/JOP chain construction  

---

## 4️⃣ Web Application Attacks (OWASP Top 10 2024 + Extended)

### **Injection Attacks**
- **SQL Injection (Comprehensive)**  
  - **Error-based SQL injection** – Extracting data via database errors  
  - **Union-based SQL injection** – Combining queries for data extraction  
  - **Boolean-based blind SQL injection** – True/false condition testing  
  - **Time-based blind SQL injection** – Response delay analysis  
  - **Out-of-band SQL injection** – Alternative data exfiltration channels  
  - **Second-order SQL injection** – Delayed payload execution  
  - **SQLi in different contexts** – Headers, cookies, JSON, XML  
- **NoSQL Injection**  
  - MongoDB injection techniques  
  - CouchDB exploitation  
  - Redis command injection  
- **Command Injection**  
  - OS command injection via web parameters  
  - Blind command injection techniques  
  - Command chaining and piping  
- **LDAP Injection**  
  - Authentication bypass  
  - Data extraction via LDAP queries  
- **XPath Injection**  
  - XML document data extraction  
  - Authentication bypass via XPath  

### **Cross-Site Scripting (XSS)**
- **Reflected XSS**  
  - URL parameter exploitation  
  - Social engineering delivery  
- **Stored XSS**  
  - Database-stored payload execution  
  - Administrative panel targeting  
- **DOM-based XSS**  
  - Client-side JavaScript exploitation  
  - Document object manipulation  
- **Advanced XSS Techniques**  
  - XSS via file upload  
  - Polyglot XSS payloads  
  - CSP bypass techniques  
  - XSS in PDF files  

### **Authentication & Session Attacks**
- **Session Management Flaws**  
  - Session fixation attacks  
  - Session hijacking via XSS/MITM  
  - Session replay attacks  
  - Concurrent session exploitation  
- **Authentication Bypass**  
  - Weak password recovery mechanisms  
  - Multi-factor authentication bypass  
  - JWT token manipulation  
  - OAuth flow manipulation  
- **Brute Force Protection Bypass**  
  - Rate limiting circumvention  
  - Account lockout bypass  
  - CAPTCHA bypass techniques  

### **Access Control Attacks**
- **Broken Access Control (OWASP #1 2024)**  
  - **Vertical privilege escalation** – Lower to higher privilege access  
  - **Horizontal privilege escalation** – Same level, different user access  
  - **IDOR (Insecure Direct Object Reference)** – Direct object manipulation  
  - **Path traversal attacks** – Directory traversal exploitation  
  - **File inclusion attacks** – LFI/RFI exploitation  

### **Advanced Web Attacks**
- **Server-Side Request Forgery (SSRF)**  
  - Internal network reconnaissance  
  - Cloud metadata service access  
  - Port scanning via SSRF  
- **XML External Entity (XXE) Injection**  
  - File disclosure via XML parsing  
  - SSRF via XXE  
  - DoS via billion laughs attack  
- **Deserialization Attacks**  
  - Java deserialization exploits  
  - PHP object injection  
  - .NET deserialization vulnerabilities  
- **Business Logic Flaws**  
  - Race condition exploitation  
  - Workflow bypass attacks  
  - Price manipulation  
- **API Security Attacks**  
  - REST API enumeration  
  - GraphQL injection  
  - API rate limiting bypass  
  - Mass assignment attacks  

---

## 5️⃣ Network Attacks & Man-in-the-Middle

### **Denial of Service (DoS/DDoS)**
- **Network Layer Attacks**  
  - **SYN Flood** – TCP connection exhaustion  
  - **UDP Flood** – Bandwidth consumption  
  - **ICMP Flood** – Ping flood attacks  
  - **Smurf Attack** – ICMP amplification  
  - **Fraggle Attack** – UDP amplification  
  - **Teardrop Attack** – Fragmented packet exploitation  
- **Application Layer Attacks**  
  - **HTTP Flood** – Application-level resource exhaustion  
  - **Slowloris** – Slow HTTP header attacks  
  - **R.U.D.Y** – Slow HTTP POST attacks  
  - **Hash collision attacks** – Algorithmic complexity attacks  

### **Man-in-the-Middle (MITM) Attacks**
- **ARP Spoofing**  
  - Network traffic interception  
  - Gateway impersonation  
  - VLAN hopping via ARP  
- **DNS Spoofing**  
  - Local DNS cache poisoning  
  - Rogue DNS server deployment  
  - DNS hijacking attacks  
- **SSL/TLS Attacks**  
  - SSL stripping attacks  
  - Certificate pinning bypass  
  - Downgrade attacks (POODLE, BEAST)  
  - Heartbleed exploitation  
- **BGP Hijacking**  
  - Route advertisement manipulation  
  - Traffic redirection attacks  

### **Network Sniffing & Packet Capture**
- **Passive Sniffing**  
  - Hub-based network monitoring  
  - Wireless packet capture  
  - Fiber optic tapping  
- **Active Sniffing**  
  - MAC flooding attacks  
  - DHCP starvation  
  - CAM table overflow  
  - ARP poisoning for traffic capture  

---

## 6️⃣ Wireless Network Attacks

### **Wi-Fi Security Attacks**
- **WEP Attacks**  
  - IV collision attacks  
  - ChopChop attacks  
  - Fragmentation attacks  
- **WPA/WPA2 Attacks**  
  - 4-way handshake capture  
  - Dictionary/brute force attacks  
  - PMKID attacks (hashcat mode 22000)  
  - WPS PIN attacks (Reaver, Bully)  
- **WPA3 Attacks**  
  - Dragonfly handshake attacks  
  - Downgrade attacks to WPA2  
- **Rogue Access Point Attacks**  
  - Evil twin AP deployment  
  - Captive portal phishing  
  - Karma attacks (probe response)  
- **Advanced Wireless Attacks**  
  - Deauthentication attacks  
  - Beacon flooding  
  - Hidden SSID discovery  
  - WDS/bridge exploitation  

### **Bluetooth Attacks**
- **Bluejacking** – Unsolicited message sending  
- **Bluesnarfing** – Unauthorized data access  
- **Bluebugging** – Device control hijacking  
- **BlueBorne** – Bluetooth stack exploitation  

---

## 7️⃣ Mobile Device Security Attacks

### **Android Attack Vectors**
- **APK Analysis & Reverse Engineering**  
  - Static code analysis  
  - Dynamic runtime analysis  
  - Certificate pinning bypass  
  - Root detection bypass  
- **Android-Specific Attacks**  
  - Intent-based attacks  
  - Broadcast receiver exploitation  
  - Content provider data leakage  
  - Shared preferences manipulation  
- **Mobile Malware**  
  - Banking trojans  
  - Spyware and stalkerware  
  - Ransomware attacks  
  - Cryptocurrency miners  

### **iOS Attack Vectors**
- **iOS Exploitation (Limited without jailbreak)**  
  - Certificate trust exploitation  
  - URL scheme hijacking  
  - Backup analysis attacks  
  - Sideloading attacks  

---

## 8️⃣ IoT & SCADA/ICS Attacks

### **IoT Device Exploitation**
- **Common IoT Vulnerabilities**  
  - Default credential attacks  
  - Firmware exploitation  
  - Insecure communication protocols  
  - Device identity spoofing  
- **IoT Network Attacks**  
  - MQTT message interception  
  - CoAP protocol exploitation  
  - Zigbee network attacks  
  - LoRaWAN security flaws  
- **Smart Home Attacks**  
  - Smart camera hijacking  
  - Smart lock manipulation  
  - Voice assistant exploitation  

### **SCADA/ICS Attacks**
- **Industrial Protocol Exploitation**  
  - Modbus protocol attacks  
  - DNP3 manipulation  
  - IEC 61850 exploitation  
- **HMI (Human Machine Interface) Attacks**  
  - HMI credential attacks  
  - Visualization system exploitation  
- **PLC (Programmable Logic Controller) Attacks**  
  - Logic bomb insertion  
  - Process manipulation  
  - Safety system bypass  

---

## 9️⃣ Cloud Security Attacks

### **Cloud Infrastructure Attacks**
- **AWS-Specific Attacks**  
  - S3 bucket misconfiguration exploitation  
  - IAM privilege escalation  
  - EC2 metadata service abuse  
  - Lambda function exploitation  
- **Azure-Specific Attacks**  
  - Azure AD enumeration  
  - Storage account exploitation  
  - Function app vulnerabilities  
- **GCP-Specific Attacks**  
  - GCS bucket enumeration  
  - Service account impersonation  
  - Cloud Function exploitation  
- **Multi-Cloud Attacks**  
  - Cross-cloud credential reuse  
  - Cloud API abuse  
  - Container escape attacks  
  - Kubernetes cluster exploitation  

---

## 🔟 AI-Enhanced Attacks (New in CEH v13)

### **AI-Powered Reconnaissance**
- **Machine Learning for Target Profiling**  
  - Automated OSINT correlation  
  - Pattern recognition in public data  
  - Behavioral analysis for social engineering  
- **AI-Driven Vulnerability Discovery**  
  - Automated code analysis  
  - Fuzzing with machine learning  
  - Zero-day discovery automation  

### **Adversarial AI Attacks**
- **Model Poisoning**  
  - Training data manipulation  
  - Backdoor insertion in ML models  
- **Model Evasion**  
  - Adversarial example generation  
  - Feature manipulation attacks  
- **Model Extraction**  
  - Black-box model stealing  
  - API-based model replication  

### **AI-Assisted Social Engineering**
- **Deepfake Technology**  
  - Voice cloning attacks  
  - Video deepfake creation  
  - AI-generated phishing content  
- **Chatbot Manipulation**  
  - AI assistant jailbreaking  
  - Prompt injection attacks  

---

## 1️⃣1️⃣ Advanced Persistent Threat (APT) Techniques

### **Maintaining Access & Persistence**
- **Windows Persistence Mechanisms**  
  - Registry run keys  
  - Service installation  
  - Scheduled task creation  
  - WMI event subscriptions  
  - DLL hijacking persistence  
- **Linux Persistence Mechanisms**  
  - Cron job modification  
  - Init script modification  
  - SSH key injection  
  - Library preloading (LD_PRELOAD)  
- **Advanced Backdoors**  
  - Fileless malware techniques  
  - Living-off-the-land binaries (LOLbins)  
  - Memory-only persistence  

### **Lateral Movement Techniques**
- **Credential Harvesting**  
  - Memory credential extraction (Mimikatz)  
  - Cached credential attacks  
  - Kerberos ticket manipulation  
- **Network Traversal**  
  - SSH tunneling  
  - RDP session hijacking  
  - WMI lateral movement  
  - PowerShell remoting abuse  

---

## 1️⃣2️⃣ Social Engineering Attacks

### **Traditional Social Engineering**
- **Phishing Variants**  
  - **Email phishing** – Mass email campaigns  
  - **Spear phishing** – Targeted individual attacks  
  - **Whaling** – Executive-level targeting  
  - **Clone phishing** – Legitimate email replication  
  - **Business Email Compromise (BEC)** – CEO fraud  
- **Voice-based Attacks**  
  - **Vishing** – Voice phishing over phone  
  - **IVR manipulation** – Interactive voice response abuse  
- **SMS-based Attacks**  
  - **Smishing** – SMS phishing  
  - **SIM swapping** – Mobile number hijacking  

### **Physical Social Engineering**
- **Physical Infiltration**  
  - **Tailgating** – Following authorized personnel  
  - **Baiting** – USB drop attacks  
  - **Pretexting** – Authority impersonation  
- **Dumpster Diving**  
  - Information gathering from discarded materials  
  - Document reconstruction attacks  

### **Digital Social Engineering**
- **Watering Hole Attacks**  
  - Website compromise targeting specific groups  
  - Drive-by download deployment  
- **Social Media Exploitation**  
  - LinkedIn reconnaissance  
  - Facebook relationship mapping  
  - Twitter sentiment analysis for targeting  

---

## 1️⃣3️⃣ Malware Analysis & Types

### **Malware Categories**
- **Viruses**  
  - File infector viruses  
  - Macro viruses  
  - Boot sector viruses  
  - Multipartite viruses  
- **Worms**  
  - Network worms  
  - Email worms  
  - USB worms  
- **Trojans**  
  - Remote Access Trojans (RATs)  
  - Banking trojans  
  - Downloader trojans  
  - Rootkit trojans  
- **Ransomware**  
  - Crypto-ransomware  
  - Locker ransomware  
  - Ransomware-as-a-Service (RaaS)  
- **Advanced Malware**  
  - Fileless malware  
  - Polymorphic malware  
  - Metamorphic malware  
  - AI-powered malware  

---

## 📊 Comprehensive Attack → Tool Cross-Reference Matrix

| **Attack Category** | **Specific Attack** | **Primary Tool** | **Alternative Tools** | **Detection Method** |
|---------------------|--------------------|--------------------|----------------------|---------------------|
| **OSINT/Recon** | Email harvesting | theHarvester | Hunter.io, Maltego | Email validation |
| | Subdomain discovery | subfinder | Amass, dnsrecon | DNS monitoring |
| | Technology fingerprinting | whatweb | Wappalyzer, BuiltWith | Response analysis |
| **Network Scanning** | Port scanning | nmap | rustscan, masscan | IDS signatures |
| | Service enumeration | nmap -sV | banner grabbing | Service monitoring |
| | Vulnerability scanning | Nessus | OpenVAS, Qualys | Vuln databases |
| **Web Application** | SQL injection | sqlmap | Havij, jSQL | WAF logs |
| | XSS testing | XSSer | Burp Suite, OWASP ZAP | Content filtering |
| | Directory bruteforce | gobuster | dirb, ffuf | Access logs |
| **Password Attacks** | Online brute force | hydra | Medusa, ncrack | Account lockouts |
| | Hash cracking | hashcat | John the Ripper | Hash monitoring |
| | Credential stuffing | Custom scripts | Sentry MBA | Login analytics |
| **Wireless** | WPA handshake capture | airodump-ng | Kismet | WIDS alerts |
| | WPA cracking | aircrack-ng | hashcat mode 22000 | Strong passwords |
| | Evil twin AP | hostapd | WiFi Pineapple | RF monitoring |
| **Social Engineering** | Phishing campaigns | setoolkit | Gophish, King Phisher | Email security |
| | Credential harvesting | Evilginx | Modlishka | MFA enforcement |
| **Exploitation** | Exploit deployment | msfconsole | Exploit-DB | SIEM correlation |
| | Payload creation | msfvenom | Veil, TheFatRat | AV signatures |
| | Post-exploitation | Meterpreter | Cobalt Strike | EDR detection |
| **Network Attacks** | ARP spoofing | ettercap | Bettercap, arpspoof | ARP monitoring |
| | DNS spoofing | dnsspoof | ettercap | DNS monitoring |
| | Packet sniffing | Wireshark | tcpdump, tshark | Encryption |
| **DoS/DDoS** | SYN flood | hping3 | Scapy, LOIC | Rate limiting |
| | HTTP flood | slowloris | HOIC, R.U.D.Y | DDoS protection |
| **Mobile** | APK analysis | apktool | jadx, dex2jar | App store review |
| | Dynamic analysis | Frida | objection | Runtime protection |
| **IoT** | Device discovery | nmap IoT scripts | Shodan, Censys | Network segmentation |
| | Protocol exploitation | Custom scripts | IoT Inspector | Protocol monitoring |
| **Cloud** | S3 bucket enumeration | aws cli | bucket_finder | CloudTrail logs |
| | IAM privilege escalation | pacu | ScoutSuite | IAM monitoring |
| **AI/ML** | Model extraction | Custom scripts | Model extraction tools | Access logging |
| | Adversarial examples | Foolbox | ART | Input validation |
| **Steganography** | Image steganography | steghide | OpenStego, StegSolve | File analysis |
| | Data exfiltration | Custom tools | Covert channels | DLP solutions |
| **Forensics** | Memory analysis | Volatility | Rekall | Memory dumps |
| | Disk analysis | Autopsy | Sleuth Kit | Disk imaging |

---

## 🎯 CEH v13 Exam Success Strategy

### **High-Probability Attack Categories (80% of Questions)**
1. **Web Application Attacks** – OWASP Top 10 focus
2. **Network Reconnaissance** – nmap and enumeration
3. **Password Attacks** – All variants
4. **Wireless Security** – WPA/WPA2 methodology
5. **Social Engineering** – Phishing and pretexting
6. **Malware Analysis** – Types and detection
7. **AI-Enhanced Attacks** – New CEH v13 focus

### **Study Priority Ranking**
- **Priority 1 (Must Know):** Web apps, Network scanning, Password attacks
- **Priority 2 (Important):** Wireless, Social engineering, Malware
- **Priority 3 (Emerging):** AI attacks, IoT security, Cloud attacks
---
