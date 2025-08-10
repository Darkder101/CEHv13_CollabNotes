# CEH v13 Attack Techniques & Tool Cross-Reference

This document covers:
1. **Attack Types & Subtypes** .
2. **Tool Quick-Reference Table**.

---

## 1️⃣ Reconnaissance Attacks

**Passive Recon** – No direct contact with target  
- Google Dorking  
- Whois lookups  
- Social media profiling  
- DNS enumeration (dig, dnsrecon)  
- Archive scraping (Wayback Machine)  
- Metadata extraction (exiftool)  
- Certificate transparency log mining  

**Active Recon** – Direct interaction with target  
- Ping sweeps  
- Nmap scanning  
- Banner grabbing  
- DNS zone transfer attempts  
- SMTP VRFY/EXPN probing  
- SNMP sweeps  

---

## 2️⃣ Scanning & Enumeration Attacks

- **Port scanning** – TCP Connect, SYN scan, Xmas scan, FIN scan, NULL scan  
- **Vulnerability scanning** – Nessus, OpenVAS, Qualys  
- **NetBIOS enumeration** – nbtstat, enum4linux  
- **SNMP enumeration** – snmpwalk  
- **SMTP enumeration** – VRFY/EXPN commands  
- **LDAP enumeration** – ldapsearch, NSE scripts  
- **NTP enumeration** – ntptrace, monlist queries  
- **IPv6 scanning** – address space mapping, neighbor discovery abuse  

---

## 3️⃣ Gaining Access Attacks

### a. Network-Level Attacks
- **DoS/DDoS**  
  - SYN Flood  
  - UDP Flood  
  - HTTP Flood  
  - Smurf Attack  
  - Fraggle Attack  
  - Slowloris  
  - Ping of Death  
  - Teardrop Attack  
- **Man-in-the-Middle (MITM)**  
  - ARP spoofing  
  - DNS spoofing  
  - HTTPS stripping  
  - BGP hijacking  
- **Packet Sniffing**  
  - Passive sniffing  
  - Active sniffing (MAC flooding)  
  - DHCP starvation & rogue DHCP  

### b. System-Level Attacks
- **Password attacks**  
  - Brute force  
  - Dictionary attack  
  - Hybrid attack  
  - Rainbow table attack  
- **Buffer Overflow**  
  - Stack-based  
  - Heap-based  
  - Integer overflow  
  - Format string vulnerability  
- **Privilege Escalation**  
  - Vertical escalation  
  - Horizontal escalation  
  - Exploiting misconfigurations (SUID/SGID, weak ACLs)  
- **Remote Code Execution (RCE)**  
  - Exploiting vulnerable services  
  - Deserialization attacks  

### c. Application-Level Attacks

#### **Web Application Attacks (OWASP Top 10 & more)**  
- Injection Attacks:  
  - SQL Injection (Error-based, Blind, Time-based, Union-based, Out-of-Band)  
  - Command Injection  
  - LDAP Injection  
  - XML Injection  
- Cross-Site Scripting (XSS):  
  - Reflected XSS  
  - Stored XSS  
  - DOM-based XSS  
  - Self-XSS  
- Cross-Site Request Forgery (CSRF)  
- Broken Authentication & Session Management  
- Security Misconfiguration Exploits  
- Sensitive Data Exposure  
- Broken Access Control  
  - IDOR (Insecure Direct Object Reference)  
  - Privilege escalation via parameter tampering  
- XML External Entity (XXE) Injection  
- Server-Side Request Forgery (SSRF)  
- Path Traversal / Directory Traversal  
- File Inclusion  
  - Local File Inclusion (LFI)  
  - Remote File Inclusion (RFI)  
- Business Logic Attacks  
- API-specific attacks  
  - Mass assignment  
  - Excessive data exposure  
  - Rate limiting bypass  

#### **Session Attacks**  
- Session hijacking  
- Session fixation  
- Session replay attacks  
- JWT token manipulation  

#### **Other Application-Level Attacks**  
- Clickjacking (UI redress attacks)  
- HTML5-based attacks (WebSockets abuse, LocalStorage theft)  
- Cache poisoning  
- Template injection (SSTI)  
- Deserialization attacks (Java, PHP, .NET)  
- Race condition exploitation  
- Log injection  

### d. Wireless Attacks
- **WEP/WPA/WPA2/WPA3 cracking**  
- **Evil Twin AP**  
- **Deauthentication attack**  
- **Rogue access point**  
- **Beacon flooding**  
- **Bluetooth attacks** – Bluejacking, Bluesnarfing, Bluebugging  

---

## 4️⃣ Maintaining Access Attacks
- **Backdoors** – Netcat listener, custom shells  
- **Rootkits** – Kernel, Firmware, Application level  
- **Trojans** – Remote Access Trojan (RAT), Banking Trojan, Downloader  
- **Logic bombs**  
- **Web shells** – c99, b374k, Weevely  
- **Persistence mechanisms** – Scheduled tasks, registry run keys  

---

## 5️⃣ Covering Tracks Attacks
- **Log manipulation** – Clearing or altering logs  
- **Timestamp modification** – Timestomping  
- **Steganography** – Hiding data in images/audio  
- **Alternate Data Streams (ADS)** in NTFS  
- **Anti-forensic tools** – secure delete, wiping free space  

---

## 6️⃣ Social Engineering Attacks
- **Phishing** – Email-based, Spear phishing, Whaling, Clone phishing  
- **Vishing** – Voice phishing  
- **Smishing** – SMS phishing  
- **Baiting** – Offering free USB drives loaded with malware  
- **Pretexting** – Impersonating someone with authority  
- **Tailgating** – Physical security breach  
- **Quizzes & fake surveys** – Harvesting personal data  
- **Watering hole attacks** – Compromising websites visited by target group  

---

## 7️⃣ Malware Types & Subtypes
- **Viruses** – File infector, Macro virus, Boot sector virus, Multipartite  
- **Worms** – Self-replicating, network-spreading  
- **Trojan Horses** – RATs, Keyloggers, Downloader trojans  
- **Ransomware** – CryptoLocker, WannaCry, Ryuk  
- **Spyware** – Keyloggers, Screen scrapers, Browser hijackers  
- **Adware** – Ad-injection software  
- **Fileless malware** – Living off the land (LOLbins) attacks  
- **Polymorphic & metamorphic malware**  

---

## 8️⃣ Insider Threat Attacks
- **Malicious insider** – Employee sabotage, data theft  
- **Negligent insider** – Accidental data leaks  
- **Compromised insider** – Account takeover by attacker  

---

## 9️⃣ Cloud & Virtualization Attacks
- **Cloud Misconfiguration Exploits** – Public S3 buckets, overly permissive IAM roles  
- **VM Escape** – Breaking out of VM to host  
- **Container Breakout** – Escaping Docker/Kubernetes containers  
- **Credential harvesting from cloud metadata services**  
- **Cloud API abuse** – Insecure tokens, replay attacks  

---

## 1️⃣0️⃣ IoT & SCADA Attacks
- **IoT exploitation** – Default credentials, firmware exploits, API abuse  
- **SCADA/ICS attacks** – Modbus spoofing, Stuxnet-style attacks, unauthorized command injection  
- **Physical tampering with sensors/actuators**  

---

# 📊 CEH Attack Type ↔ Tool Cross-Reference Table

| **Attack Type**                         | **Primary Tool**           | **Alternate Tool(s)**                           |
|------------------------------------------|-----------------------------|-------------------------------------------------|
| Find emails / employee info (OSINT)     | theHarvester                | Hunter.io, Netcraft                            |
| Find subdomains / DNS mapping           | subfinder                   | dnsrecon, dnsdumpster.com                      |
| Domain registration info                | whois                       | Netcraft                                       |
| Query DNS records                       | dig / nslookup              | dnsrecon -t axfr                               |
| Port scanning                           | nmap -sV                    | rustscan (+ nmap deep scan)                    |
| Enumerate SMB shares / Windows info     | enum4linux                  | smbclient, nbtstat                             |
| SNMP information                        | snmpwalk                    | nmap --script=snmp*                            |
| NTP trace                               | ntptrace                    | —                                               |
| Exploit vulnerable service              | msfconsole                  | searchsploit                                    |
| Create payload                          | msfvenom                     | Veil-Evasion                                   |
| Brute-force credentials                 | hydra                        | Medusa                                         |
| SQL Injection                           | sqlmap                       | Havij                                          |
| Open reverse shell                      | netcat                       | msfconsole payload                             |
| Analyze captured traffic                | Wireshark                    | tshark                                         |
| Detect CMS / technology                 | Wappalyzer                   | whatweb                                        |
| Bypass / Detect WAF                     | wafw00f                      | —                                               |
| Intercept HTTP requests                 | Burp Suite                   | OWASP ZAP                                      |
| Directory brute-force                   | gobuster                     | dirb                                           |
| Capture WPA handshake                   | airodump-ng                  | Kismet                                         |
| Crack WPA key                           | aircrack-ng                  | hashcat, john                                  |
| Phishing / Clone login page             | zphisher                     | setoolkit                                      |
| Trick victim into enabling webcam       | camphish                     | —                                               |
| Crack hash                              | hashcat                      | john the ripper                                |
| Generate hash                           | md5sum / hashcalc            | CyberChef                                      |
| HTTP DoS                                | goldeneye                    | LOIC, HOIC                                     |
| Detect intrusion                        | Snort                        | Suricata                                       |
| Vulnerability scanning                  | Nessus Essentials            | OpenVAS                                        |
| Deploy honeypot                         | HoneyBot                     | pentbox                                        |

---
