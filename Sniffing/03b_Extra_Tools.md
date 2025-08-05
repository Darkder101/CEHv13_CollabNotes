## Objective
Recognize and apply common **sniffing tools** used for attacks, analysis, and detection in ethical hacking.

---

## 🔹 Tool Overview & Usage Scenarios

| Tool            | Key Features / Usage                                     | Notes / CEH Tip                          |
|-----------------|----------------------------------------------------------|------------------------------------------|
| **tcpdump**     | CLI-based; lightweight packet sniffer                    | ✅ Use in Linux, good for scripting       |
| **Ettercap**    | Sniffing + MITM + spoofing toolkit (ARP/DNS etc.)        | ✅ Strong lab use for ARP spoofing        |
| **Cain & Abel** | Legacy GUI tool: ARP spoofing, sniffing, cracking        | ⚠️ Windows-only; often flagged by AV      |
| **dsniff**      | Collection of sniffers: `arpspoof`, `dnsspoof`, etc.     | ✅ Command-line; great for CEH labs       |
| **Ngrep**       | Grep-like tool for packet payloads                       | ✅ Find strings (e.g., “password”)        |
| **NetworkMiner**| GUI-based forensic tool; extracts files, sessions        | ✅ Great for offline `.pcap` analysis     |
| **Snort**       | IDS/IPS tool with sniffing + rule-based detection        | ✅ Not just sniffing; also detection      |
| **MITMf**       | Powerful MITM attack framework with plugin support       | ⚠️ May require setup (Python + modules)   |
| **Wireshark**   | Full GUI packet analyzer                                 | ✅ Already covered above                  |

---

## 🔹 Tool-by-Tool Use Case Summary

### 🧪 tcpdump
- Command-line packet capture tool.
- Works well in headless or server environments.
- Example:
  ```bash
  tcpdump -i eth0 port 80

### 🧪 Ettercap
- Launch **MITM attacks**, sniff traffic, and inject payloads.
- Available in both **GUI and CLI** versions.
- **Use-case:** ARP poisoning, DNS spoofing.
	
---
	
### 🧪 Cain & Abel
- **GUI tool** (Windows-only).
- Performs:
  - ARP poisoning
	- Sniffing credentials from **Telnet**, **FTP**, **POP3**
	- Password cracking (including hashes and VoIP)
	
---
	
### 🧪 dsniff Suite
- Collection of CLI sniffing tools:
	- `arpspoof` – ARP poisoning
	- `dnsspoof` – DNS spoofing
	- `msgsnarf` – Instant Messaging sniffing
	- `filesnarf` – File sniffing over NFS
	
---
	
### 🧪 Ngrep
- **Pattern-based sniffing tool** (like `grep` for network traffic).
- Searches for strings in packet payloads.
- **Example:**
	 ```bash
	  ngrep -q -d eth0 "password"
	
### 🧪 NetworkMiner
- **Passive sniffing** and **file carving tool**.
- GUI-based; ideal for **forensic analysis**.
- Extracts:
  - Usernames / passwords
  - Downloaded files  
	- Hostnames and session data  
	
---
	
### 🧪 Snort
- **IDS/IPS** and packet analyzer in one.
- Detects **malicious payloads** using **predefined rules**.
- Example:
	 - Detect FTP login attempts using signature-based detection.
	
---
	
### 🧪 MITMf (Man-in-the-Middle Framework)
- **Modular MITM attack platform** with plugin support.
- Can perform:
  - SSL stripping
  - DNS spoofing  
	- SMB relay attacks
  
---
	
## 🔹 CEH Exam Tip
	
> 🧠 Know which tool is best for each attack or analysis scenario:
	
| **Scenario**            | **Best Tools**                     |
|-------------------------|-------------------------------------|
| ARP/DNS Spoofing        | Ettercap, dsniff                   |
| Passive Sniffing        | Wireshark, NetworkMiner            |
| CLI Environments        | tcpdump, ngrep                     |
| Credential Harvesting   | Cain & Abel, Ettercap, dsniff      |
	
---
> ✅ *Matching tools to scenarios is a common question type in CEH v13. Review each tool's primary function and platform compatibility.
