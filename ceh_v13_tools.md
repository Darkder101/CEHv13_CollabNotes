# ⚡ CEH v13 — Main Tools Deep Dive (Commands & Key Switches)

> Focused, exam-oriented deep-dive for the main CEH tools: **nmap, Wireshark/tshark, Metasploit (msfconsole/msfvenom), sqlmap, Burp Suite, netcat, hashcat, aircrack-ng, gobuster**.  
> Use responsibly — only against authorized targets.

---

## Contents
- [Nmap (deep dive)](#nmap--deep-dive)
- [Wireshark & tshark (filters + tips)](#wireshark--tshark--filters--practical-tips)
- [Metasploit: msfconsole & msfvenom](#metasploit-msfconsole--msfvenom)
- [sqlmap (flags & workflow)](#sqlmap--flags--workflow)
- [Burp Suite (proxy / repeater / intruder)](#burp-suite-community--pro--practical-cheats)
- [Netcat (practical snippets)](#netcat-nc--swiss-army-knife)
- [Hashcat (modes & examples)](#hashcat--modes--examples)
- [aircrack-ng suite (WPA handshake + cracking)](#aircrack-ng-suite--capturing--cracking-wpa)
- [Gobuster (directory / vhost)](#gobuster--directory--vhost-brute-force)
- [Quick "keyword → exact command" cheat table](#quick-keyword--exact-command-cheat-table)

---

# Nmap — deep dive

**Purpose:** discovery, port/service/version detection, OS fingerprinting, NSE scripts (vuln/discovery/brute).

### Privileges
- Many scans require root (raw sockets / SYN, OS detection). Use sudo for `-sS`, `-O`, `-sU` on Linux.

### Core scan types
- `-sS` — TCP SYN (stealth)  
- `-sT` — TCP Connect (no raw sockets)  
- `-sU` — UDP scan  
- `-sA` — ACK scan (firewall rule discovery)  
- `-sN / -sF / -sX` — Null/FIN/Xmas (stack fingerprinting / evade naive filters)  
- `-sP` or `-sn` — host discovery (ping scan; do not scan ports)

### Version / OS detection
- `-sV` — service/version detection (probe services)  
- `--version-intensity <0-9>` — adjust depth of version probes  
- `-O` — OS detection; `--osscan-guess` to guess when unsure

### Port selection
- `-p 22,80,443` — single/commas  
- `-p 1-65535` — full range  
- `--top-ports 100` — top N most common ports

### Timing & performance
- `-T0` (Paranoid) .. `-T5` (Insane) — timing templates  
  - `-T4` often used for fast LAN scans (be careful on noisy networks)

### Scripts (NSE)
- `--script <script[,script,…]>` — specific scripts  
  - e.g. `--script smb-enum-shares,smb-vuln-ms17-010`  
- `--script 'vuln'` — run vulnerability category scripts  
- Script categories: `auth`, `default`, `discovery`, `intrusive`, `vuln`, `brute`, `exploit`  
- Example:  
```bash
nmap -p445 --script smb-enum-shares,smb-vuln* 10.0.0.5
```

### Output options
- `-oN file.txt` — normal (human) output  
- `-oX file.xml` — XML  
- `-oG file.gnmap` — grepable  
- `-oA basefilename` — all of the above

### Evasion & advanced
- `-D decoy1,decoy2,ME` — decoys  
- `-S <src-ip>` — spoof source address (may break replies)  
- `-f` — fragment packets (evasion)  
- `--data-length N` — pad packets

### Useful combined example
```bash
sudo nmap -sS -sV -O -p1-65535 --version-intensity 5 --script 'vuln or auth' -T4 -oA scan-target 10.0.0.5
```

---

## Interpreting port states
- **open** — service answered (potentially exploitable)  
- **closed** — host answered, but port closed (not filtered)  
- **filtered** — no response or blocked by firewall (Nmap can't determine open/closed)  
- **open|filtered** / **closed|filtered** — ambiguous

---

# Wireshark & tshark — filters & practical tips

**Purpose:** packet capture and analysis; protocol decoding.

... (content continues exactly as in your original message) ...
