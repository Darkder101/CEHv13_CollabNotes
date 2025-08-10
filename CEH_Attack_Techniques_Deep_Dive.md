# 🛡 CEH Attack Techniques Deep Dive

This file covers **most attack types and their sub-types** for CEH v13.  
Use it to quickly identify an attack from a scenario and recall detection & prevention methods.

---

## 1️⃣ Reconnaissance Attacks
**Passive Recon** – No direct contact with target  
- Google Dorking  
- Whois lookups  
- Social media profiling  
- DNS enumeration (dig, dnsrecon)  

**Active Recon** – Direct interaction with target  
- Ping sweeps  
- Nmap scanning  
- Banner grabbing  

---

## 2️⃣ Scanning & Enumeration Attacks
- **Port scanning** – TCP Connect, SYN scan, Xmas scan  
- **Vulnerability scanning** – Nessus, OpenVAS  
- **NetBIOS enumeration** – nbtstat, enum4linux  
- **SNMP enumeration** – snmpwalk  
- **SMTP enumeration** – VRFY/EXPN commands  

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
- **Man-in-the-Middle (MITM)**  
  - ARP spoofing  
  - DNS spoofing  
  - HTTPS stripping  
- **Packet Sniffing**  
  - Passive sniffing  
  - Active sniffing (MAC flooding)  

### b. System-Level Attacks
- **Password attacks**  
  - Brute force  
  - Dictionary attack  
  - Rainbow table attack  
- **Buffer Overflow**  
  - Stack-based  
  - Heap-based  
- **Privilege Escalation**  
  - Vertical escalation  
  - Horizontal escalation  

### c. Application-Level Attacks
- **Web Application Attacks**  
  - SQL Injection (Error-based, Blind, Time-based, Union-based)  
  - XSS (Reflected, Stored, DOM-based)  
  - CSRF  
  - Command Injection  
  - File Inclusion (LFI/RFI)  
- **Session Attacks**  
  - Session hijacking  
  - Session fixation  

### d. Wireless Attacks
- **WEP/WPA/WPA2 cracking**  
- **Evil Twin AP**  
- **Deauthentication attack**  
- **Rogue access point**  

---

## 4️⃣ Maintaining Access Attacks
- **Backdoors** – Netcat listener, custom shells  
- **Rootkits** – Kernel, Firmware, Application level  
- **Trojans** – Remote Access Trojan (RAT), Banking Trojan  
- **Logic bombs**  

---

## 5️⃣ Covering Tracks Attacks
- **Log manipulation** – Clearing or altering logs  
- **Timestamp modification** – Timestomping  
- **Steganography** – Hiding data in images/audio  

---

## 6️⃣ Social Engineering Attacks
- **Phishing** – Email-based, Spear phishing, Whaling  
- **Vishing** – Voice phishing  
- **Smishing** – SMS phishing  
- **Baiting** – Offering free USB drives loaded with malware  
- **Pretexting** – Impersonating someone with authority  
- **Tailgating** – Physical security breach  

---

## 7️⃣ Malware Types & Subtypes
- **Viruses** – File infector, Macro virus, Boot sector virus  
- **Worms** – Self-replicating, network-spreading  
- **Trojan Horses** – RATs, Keyloggers, Downloader trojans  
- **Ransomware** – CryptoLocker, WannaCry  
- **Spyware** – Keyloggers, Screen scrapers  
- **Adware** – Ad-injection software  

---

## 8️⃣ Insider Threat Attacks
- **Malicious insider** – Employee sabotage, data theft  
- **Negligent insider** – Accidental data leaks  
- **Compromised insider** – Account takeover by attacker  

---

## 9️⃣ Cloud & Virtualization Attacks
- **Cloud Misconfiguration Exploits**  
- **VM Escape** – Breaking out of VM to host  
- **Container Breakout** – Escaping Docker/Kubernetes containers  

---

## 1️⃣0️⃣ IoT & SCADA Attacks
- **IoT exploitation** – Default credentials, firmware exploits  
- **SCADA/ICS attacks** – Modbus spoofing, Stuxnet-style attacks  

---

## 📌 Exam Tip
- Always connect: **Attack → Tools → Detection → Prevention**
- Scenario questions often disguise attack type by describing **symptoms** (e.g., “high SYN packets with no completion” = SYN flood).

