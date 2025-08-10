# CEH v13 Tool Quick-Decision Flowchart
**Start:** Look for keywords in the exam question. Follow the matching branch.

---

## 1. Introduction to Ethical Hacking & Information Security
**Keyword:** "Information security fundamentals" / "CIA triad"  
→ **Concept:** Confidentiality, Integrity, Availability  
→ **Framework:** NIST Cybersecurity Framework

**Keyword:** "Ethical hacking methodology"  
→ **Framework:** 5-Phase Methodology (Reconnaissance → Scanning → Gaining Access → Maintaining Access → Covering Tracks)

**Keyword:** "Vulnerability assessment vs penetration testing"  
→ **Tool:** Nessus (VA) vs Metasploit (PT)

---

## 2. Footprinting and Reconnaissance
**Keyword:** "Find emails" / "employee info" / "OSINT"  
→ **Tool:** theHarvester  
→ **Alt:** Hunter.io, Maltego, Recon-ng, Shodan

**Keyword:** "Find subdomains" / "DNS mapping"  
→ **Tool:** subfinder  
→ **Alt:** dnsrecon, dnsdumpster.com, Sublist3r, Amass

**Keyword:** "Social media intelligence"  
→ **Tool:** Sherlock, Social-Engineer Toolkit (SET)  
→ **Alt:** Maltego, SpiderFoot

**Keyword:** "Website footprinting"  
→ **Tool:** Wayback Machine, HTTrack  
→ **Alt:** wget, Burp Suite Spider

**Keyword:** "Google dorking" / "Search engine reconnaissance"  
→ **Tool:** Google Hacking Database (GHDB)  
→ **Alt:** DorkBot, Pagodo

**Keyword:** "Get domain registration info"  
→ **Tool:** whois  
→ **Alt:** Netcraft, domaintools.com

**Keyword:** "Query DNS records"  
→ **Tool:** dig / nslookup  
→ **Alt:** `dnsrecon -t axfr` (zone transfer), fierce

---

## 3. Scanning Networks
**Keyword:** "Find open ports/services"  
→ **Tool:** `nmap -sV -sC`  
→ **Alt:** rustscan, masscan, unicornscan

**Keyword:** "TCP connect scan"  
→ **Tool:** `nmap -sT`

**Keyword:** "SYN stealth scan"  
→ **Tool:** `nmap -sS`

**Keyword:** "UDP scan"  
→ **Tool:** `nmap -sU`

**Keyword:** "Vulnerability scanning"  
→ **Tool:** Nessus Essentials  
→ **Alt:** OpenVAS, Qualys, Rapid7 Nexpose

**Keyword:** "Banner grabbing"  
→ **Tool:** telnet, nc (netcat)  
→ **Alt:** `nmap -sV`

**Keyword:** "OS fingerprinting"  
→ **Tool:** `nmap -O`  
→ **Alt:** p0f, Xprobe2

---

## 4. Enumeration
**Keyword:** "Enumerate SMB shares / Windows info"  
→ **Tool:** enum4linux  
→ **Alt:** smbclient, rpcclient, smbmap

**Keyword:** "SNMP enumeration"  
→ **Tool:** snmpwalk  
→ **Alt:** `nmap --script=snmp*`, snmpenum

**Keyword:** "LDAP enumeration"  
→ **Tool:** ldapsearch  
→ **Alt:** JXplorer, Apache Directory Studio

**Keyword:** "NetBIOS enumeration"  
→ **Tool:** nbtstat  
→ **Alt:** nbtscan

**Keyword:** "NFS enumeration"  
→ **Tool:** showmount  
→ **Alt:** `nmap --script=nfs*`

**Keyword:** "FTP enumeration"  
→ **Tool:** anonymous FTP login  
→ **Alt:** `nmap --script=ftp*`

---

## 5. Vulnerability Analysis
**Keyword:** "Vulnerability research"  
→ **Tool:** National Vulnerability Database (NVD)  
→ **Alt:** CVE Details, Exploit-DB

**Keyword:** "Vulnerability scoring"  
→ **Framework:** CVSS (Common Vulnerability Scoring System)

**Keyword:** "Vulnerability classification"  
→ **Framework:** CWE (Common Weakness Enumeration)

---

## 6. System Hacking
**Keyword:** "Password cracking"  
→ **Tool:** hashcat  
→ **Alt:** John the Ripper, Hydra, Medusa

**Keyword:** "Dictionary attack"  
→ **Tool:** hashcat with wordlist  
→ **Alt:** John with --wordlist

**Keyword:** "Brute force attack"  
→ **Tool:** hydra  
→ **Alt:** Medusa, Ncrack

**Keyword:** "Rainbow table attack"  
→ **Tool:** RainbowCrack  
→ **Alt:** Ophcrack

**Keyword:** "Privilege escalation"  
→ **Tool:** LinEnum (Linux), WinPEAS (Windows)  
→ **Alt:** GTFOBins, LOLBAS

**Keyword:** "Hide files and directories"  
→ **Tool:** Alternate Data Streams (Windows)  
→ **Alt:** Steghide (steganography)

**Keyword:** "Covering tracks"  
→ **Tool:** Clear event logs, modify timestamps  
→ **Alt:** ccleaner, sdelete

---

## 7. Malware Threats
**Keyword:** "Trojan analysis"  
→ **Tool:** Wireshark (network analysis)  
→ **Alt:** Process Monitor, Regshot

**Keyword:** "Virus creation" / "Payload generation"  
→ **Tool:** msfvenom  
→ **Alt:** Veil-Evasion, TheFatRat

**Keyword:** "Malware analysis sandbox"  
→ **Tool:** Cuckoo Sandbox  
→ **Alt:** ANY.RUN, Joe Sandbox

**Keyword:** "APT detection"  
→ **Tool:** YARA rules  
→ **Alt:** Snort IDS

---

## 8. Sniffing
**Keyword:** "Network packet capture"  
→ **Tool:** Wireshark  
→ **Alt:** tcpdump, tshark

**Keyword:** "ARP spoofing"  
→ **Tool:** ettercap  
→ **Alt:** driftnet, arpspoof

**Keyword:** "DNS spoofing"  
→ **Tool:** dnsspoof  
→ **Alt:** ettercap DNS plugin

**Keyword:** "MAC flooding"  
→ **Tool:** macof

**Keyword:** "Switch port stealing"  
→ **Tool:** yersinia

---

## 9. Social Engineering
**Keyword:** "Phishing" / "Clone login page"  
→ **Tool:** zphisher  
→ **Alt:** Social-Engineer Toolkit (SET), Gophish

**Keyword:** "Spear phishing"  
→ **Tool:** SET (targeted phishing)

**Keyword:** "Pretexting"  
→ **Tool:** SET (human-based attacks)

**Keyword:** "Baiting"  
→ **Tool:** USB drop attacks, malicious downloads

**Keyword:** "Elicitation techniques"  
→ **Method:** Open-ended questions, flattery

---

## 10. Denial-of-Service
**Keyword:** "HTTP DoS"  
→ **Tool:** goldeneye  
→ **Alt:** LOIC, HOIC, slowloris

**Keyword:** "SYN flood attack"  
→ **Tool:** hping3  
→ **Alt:** nping

**Keyword:** "UDP flood"  
→ **Tool:** hping3 -2  
→ **Alt:** UDP Unicorn

**Keyword:** "Ping of Death"  
→ **Tool:** ping -s 65507

**Keyword:** "Smurf attack"  
→ **Tool:** smurf.c

**Keyword:** "DDoS amplification"  
→ **Method:** DNS amplification, NTP amplification

---

## 11. Session Hijacking
**Keyword:** "Session fixation"  
→ **Tool:** Burp Suite  
→ **Alt:** OWASP ZAP

**Keyword:** "Cross-site scripting (XSS)"  
→ **Tool:** XSStrike  
→ **Alt:** BeEF, XSS Hunter

**Keyword:** "Session prediction"  
→ **Tool:** Burp Suite Sequencer

**Keyword:** "Session replay attack"  
→ **Tool:** Ettercap filters

---

## 12. Evading IDS, Firewalls, and Honeypots
**Keyword:** "IDS evasion"  
→ **Tool:** fragrouter  
→ **Alt:** nmap fragmentation (-f)

**Keyword:** "Firewall evasion"  
→ **Tool:** nmap decoys (-D)  
→ **Alt:** proxychains

**Keyword:** "Honeypot detection"  
→ **Tool:** Send  
→ **Alt:** Honeypot Hunter

**Keyword:** "Packet fragmentation"  
→ **Tool:** `nmap -f`

**Keyword:** "Source routing"  
→ **Tool:** `nmap --ip-options`

**Keyword:** "Timing attacks"  
→ **Tool:** `nmap -T0` (paranoid timing)

---

## 13. Web Applications
**Keyword:** "Web application fingerprinting"  
→ **Tool:** Wappalyzer  
→ **Alt:** whatweb, BuiltWith

**Keyword:** "Directory brute-force"  
→ **Tool:** gobuster  
→ **Alt:** dirb, dirbuster, ffuf

**Keyword:** "SQL Injection"  
→ **Tool:** sqlmap  
→ **Alt:** Havij, jsql-injection

**Keyword:** "Cross-Site Scripting (XSS)"  
→ **Tool:** XSStrike  
→ **Alt:** BeEF

**Keyword:** "Bypass WAF" / "Detect WAF"  
→ **Tool:** wafw00f  
→ **Alt:** CloudFlair

**Keyword:** "Intercept HTTP requests"  
→ **Tool:** Burp Suite  
→ **Alt:** OWASP ZAP

**Keyword:** "Command injection"  
→ **Tool:** commix  
→ **Alt:** Manual testing with Burp Suite

**Keyword:** "File inclusion (LFI/RFI)"  
→ **Tool:** fimap  
→ **Alt:** LFISuite

**Keyword:** "Parameter tampering"  
→ **Tool:** Burp Suite Intruder  
→ **Alt:** OWASP ZAP Fuzzer

---

## 14. Web API Testing
**Keyword:** "REST API testing"  
→ **Tool:** Postman  
→ **Alt:** curl, HTTPie

**Keyword:** "SOAP API testing"  
→ **Tool:** SoapUI  
→ **Alt:** Burp Suite

**Keyword:** "GraphQL injection"  
→ **Tool:** GraphQL Voyager  
→ **Alt:** InQL Burp Extension

**Keyword:** "API fuzzing"  
→ **Tool:** RESTler  
→ **Alt:** Wfuzz

---

## 15. SQL Injection
**Keyword:** "Error-based SQL injection"  
→ **Tool:** sqlmap --technique=E

**Keyword:** "Union-based SQL injection"  
→ **Tool:** sqlmap --technique=U

**Keyword:** "Blind SQL injection"  
→ **Tool:** sqlmap --technique=B

**Keyword:** "Time-based SQL injection"  
→ **Tool:** sqlmap --technique=T

**Keyword:** "Second-order SQL injection"  
→ **Tool:** Manual testing with sqlmap

**Keyword:** "NoSQL injection"  
→ **Tool:** NoSQLMap  
→ **Alt:** Manual MongoDB injection

---

## 16. Wireless Networks
**Keyword:** "Wireless network discovery"  
→ **Tool:** airodump-ng  
→ **Alt:** Kismet, iwlist

**Keyword:** "Capture WPA handshake"  
→ **Tool:** airodump-ng  
→ **Alt:** Kismet

**Keyword:** "Crack WPA/WPA2 key"  
→ **Tool:** aircrack-ng  
→ **Alt:** hashcat, john

**Keyword:** "WPS attack"  
→ **Tool:** reaver  
→ **Alt:** bully

**Keyword:** "Evil twin attack"  
→ **Tool:** hostapd  
→ **Alt:** WiFi Pineapple

**Keyword:** "Bluetooth attacks"  
→ **Tool:** btscanner  
→ **Alt:** bluez-utils

**Keyword:** "RFID attacks"  
→ **Tool:** Proxmark3  
→ **Alt:** RFID Cloner

**Keyword:** "Deauth attack"  
→ **Tool:** aireplay-ng  
→ **Alt:** mdk3

---

## 17. Mobile Platforms
**Keyword:** "Android APK analysis"  
→ **Tool:** jadx  
→ **Alt:** dex2jar + JD-GUI, APKTool

**Keyword:** "iOS app analysis"  
→ **Tool:** class-dump  
→ **Alt:** Hopper, idb

**Keyword:** "Mobile device rooting/jailbreaking"  
→ **Tool:** KingRoot (Android)  
→ **Alt:** checkra1n (iOS)

**Keyword:** "Mobile app dynamic analysis"  
→ **Tool:** Frida  
→ **Alt:** Xposed Framework

**Keyword:** "Mobile malware analysis"  
→ **Tool:** MobSF (Mobile Security Framework)  
→ **Alt:** AndroGuard

**Keyword:** "SMS spoofing"  
→ **Tool:** SMS spoofing apps  
→ **Alt:** AT commands

---

## 18. IoT and OT Hacking
**Keyword:** "IoT device discovery"  
→ **Tool:** Shodan  
→ **Alt:** Censys, BinaryEdge

**Keyword:** "Firmware analysis"  
→ **Tool:** binwalk  
→ **Alt:** firmware-mod-kit

**Keyword:** "Hardware hacking"  
→ **Tool:** Logic analyzer  
→ **Alt:** Bus Pirate, UART/JTAG debugging

**Keyword:** "MQTT broker testing"  
→ **Tool:** mosquitto_pub/sub  
→ **Alt:** MQTT.fx

**Keyword:** "CoAP testing"  
→ **Tool:** coap-cli  
→ **Alt:** Copper Chrome extension

**Keyword:** "OT/SCADA attacks"  
→ **Tool:** Metasploit industrial modules  
→ **Alt:** PLCinject

---

## 19. AI and Machine Learning
**Keyword:** "Adversarial ML attacks"  
→ **Tool:** Foolbox  
→ **Alt:** CleverHans

**Keyword:** "Model inversion attacks"  
→ **Tool:** TensorFlow Privacy  
→ **Alt:** PyTorch Opacus

**Keyword:** "Data poisoning"  
→ **Method:** Inject malicious training data

**Keyword:** "AI model stealing"  
→ **Tool:** Model extraction attacks  
→ **Alt:** Copycat CNN

**Keyword:** "Prompt injection (LLMs)"  
→ **Method:** Crafted prompts to bypass filters

**Keyword:** "Deepfake detection"  
→ **Tool:** DeeperForensics  
→ **Alt:** FaceForensics++

---

## 20. Cloud Computing
**Keyword:** "AWS penetration testing"  
→ **Tool:** ScoutSuite  
→ **Alt:** Prowler, CloudMapper

**Keyword:** "Azure security assessment"  
→ **Tool:** ScoutSuite  
→ **Alt:** Azure Security Center

**Keyword:** "GCP security review"  
→ **Tool:** ScoutSuite  
→ **Alt:** Forseti

**Keyword:** "S3 bucket enumeration"  
→ **Tool:** AWSBucketDump  
→ **Alt:** S3Scanner

**Keyword:** "Container security"  
→ **Tool:** Docker Bench  
→ **Alt:** Clair, Twistlock

**Keyword:** "Kubernetes security"  
→ **Tool:** kube-hunter  
→ **Alt:** kube-bench

**Keyword:** "Serverless security"  
→ **Tool:** ServerlessGoat  
→ **Alt:** PAWS (Pacu for AWS)

---

## 21. Cryptography
**Keyword:** "Symmetric encryption"  
→ **Algorithm:** AES, DES, 3DES

**Keyword:** "Asymmetric encryption"  
→ **Algorithm:** RSA, ECC

**Keyword:** "Hash functions"  
→ **Tool:** md5sum, sha256sum  
→ **Alt:** hashcalc, CyberChef

**Keyword:** "Digital signatures"  
→ **Tool:** GPG  
→ **Alt:** OpenSSL

**Keyword:** "PKI attacks"  
→ **Attack:** Certificate pinning bypass, weak keys

**Keyword:** "Quantum cryptography threats"  
→ **Concept:** Post-quantum cryptography

**Keyword:** "Brute-forcing encryption"  
→ **Tool:** VeraCrypt password recovery  
→ **Alt:** hashcat for encrypted archives

---

## 22. Post-Exploitation & Maintaining Access
**Keyword:** "Reverse shell"  
→ **Tool:** netcat  
→ **Alt:** msfvenom payload, PowerShell

**Keyword:** "Bind shell"  
→ **Tool:** netcat -l  
→ **Alt:** msfconsole multi/handler

**Keyword:** "Persistence mechanisms"  
→ **Tool:** Registry run keys (Windows)  
→ **Alt:** cron jobs (Linux), services

**Keyword:** "Data exfiltration"  
→ **Tool:** DNS tunneling  
→ **Alt:** HTTP/HTTPS, ICMP tunneling

**Keyword:** "Lateral movement"  
→ **Tool:** psexec  
→ **Alt:** WMI, PowerShell remoting

**Keyword:** "Anti-forensics"  
→ **Tool:** timestomp (Metasploit)  
→ **Alt:** sdelete, shred

---

## 23. Incident Response & Digital Forensics
**Keyword:** "Memory forensics"  
→ **Tool:** Volatility  
→ **Alt:** Rekall

**Keyword:** "Disk forensics"  
→ **Tool:** Autopsy  
→ **Alt:** Sleuth Kit, FTK

**Keyword:** "Network forensics"  
→ **Tool:** Wireshark  
→ **Alt:** NetworkMiner

**Keyword:** "Mobile forensics"  
→ **Tool:** Cellebrite UFED  
→ **Alt:** Oxygen Forensic Suite

**Keyword:** "Log analysis"  
→ **Tool:** Splunk  
→ **Alt:** ELK Stack (Elasticsearch, Logstash, Kibana)

---

## 24. Security Architecture & Defense
**Keyword:** "Intrusion detection"  
→ **Tool:** Snort  
→ **Alt:** Suricata, OSSEC

**Keyword:** "SIEM implementation"  
→ **Tool:** Splunk  
→ **Alt:** QRadar, ArcSight

**Keyword:** "Threat hunting"  
→ **Tool:** YARA rules  
→ **Alt:** Sigma rules

**Keyword:** "Deploy honeypot"  
→ **Tool:** HoneyBot  
→ **Alt:** T-Pot, Cowrie

**Keyword:** "Endpoint protection"  
→ **Tool:** ClamAV  
→ **Alt:** YARA, Windows Defender

---
