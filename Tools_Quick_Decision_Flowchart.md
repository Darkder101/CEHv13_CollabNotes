# 🗂 CEH v13 Tool Quick-Decision Flowchart

**Start:** Look for keywords in the exam question. Follow the matching branch.

---

## 1. Reconnaissance / Information Gathering

**Keyword:** "Find emails" / "employee info" / "OSINT"  
→ **Tool:** theHarvester  
→ **Alt:** Hunter.io, Netcraft

**Keyword:** "Find subdomains" / "DNS mapping"  
→ **Tool:** subfinder  
→ **Alt:** dnsrecon, [dnsdumpster.com](https://dnsdumpster.com)

**Keyword:** "Get domain registration info"  
→ **Tool:** whois  
→ **Alt:** Netcraft

**Keyword:** "Query DNS records"  
→ **Tool:** dig / nslookup  
→ **Alt:** `dnsrecon -t axfr` (zone transfer)

## 2. Network Scanning / Enumeration

**Keyword:** "Find open ports/services"  
→ **Tool:** `nmap -sV`  
→ **Alt:** rustscan (+ nmap deep scan)

**Keyword:** "Enumerate SMB shares / Windows info"  
→ **Tool:** enum4linux  
→ **Alt:** smbclient, nbtstat

**Keyword:** "SNMP information"  
→ **Tool:** snmpwalk  
→ **Alt:** `nmap --script=snmp*`

**Keyword:** "NTP trace"  
→ **Tool:** ntptrace

## 3. Exploitation

**Keyword:** "Exploit a vulnerable service"  
→ **Tool:** msfconsole  
→ **Alt:** searchsploit (CEH-listed)

**Keyword:** "Create payload"  
→ **Tool:** msfvenom  
→ **Alt:** Veil-Evasion (CEH-listed)

**Keyword:** "Brute-force credentials"  
→ **Tool:** hydra  
→ **Alt:** Medusa (CEH-listed)

**Keyword:** "SQL Injection"  
→ **Tool:** sqlmap  
→ **Alt:** Havij (CEH-listed)

## 4. Post-Exploitation

**Keyword:** "Open reverse shell"  
→ **Tool:** netcat  
→ **Alt:** msfconsole payload

**Keyword:** "Analyze captured traffic"  
→ **Tool:** Wireshark  
→ **Alt:** tshark (CLI version)

## 5. Web Application Testing

**Keyword:** "Detect CMS / technology"  
→ **Tool:** Wappalyzer  
→ **Alt:** whatweb (CLI, CEH-listed)

**Keyword:** "Bypass WAF" / "Detect WAF"  
→ **Tool:** wafw00f

**Keyword:** "Intercept HTTP requests"  
→ **Tool:** Burp Suite  
→ **Alt:** OWASP ZAP (CEH-listed)

**Keyword:** "Directory brute-force"  
→ **Tool:** gobuster  
→ **Alt:** dirb

## 6. Wireless Attacks

**Keyword:** "Capture WPA handshake"  
→ **Tool:** airodump-ng  
→ **Alt:** Kismet (CEH-listed)

**Keyword:** "Crack WPA key"  
→ **Tool:** aircrack-ng  
→ **Alt:** hashcat / john

## 7. Social Engineering

**Keyword:** "Phishing" / "Clone login page"  
→ **Tool:** zphisher  
→ **Alt:** setoolkit

**Keyword:** "Trick victim into enabling webcam"  
→ **Tool:** camphish

## 8. Password & Hash Attacks

**Keyword:** "Crack hash"  
→ **Tool:** hashcat  
→ **Alt:** john the ripper

**Keyword:** "Generate hash"  
→ **Tool:** md5sum / hashcalc  
→ **Alt:** CyberChef

## 9. DoS / DDoS

**Keyword:** "HTTP DoS"  
→ **Tool:** goldeneye  
→ **Alt:** LOIC / HOIC (CEH-listed)

## 10. Defensive & Detection

**Keyword:** "Detect intrusion"  
→ **Tool:** Snort

**Keyword:** "Vulnerability scanning"  
→ **Tool:** Nessus Essentials  
→ **Alt:** OpenVAS (CEH-listed)

**Keyword:** "Deploy honeypot"  
→ **Tool:** HoneyBot / pentbox

---
