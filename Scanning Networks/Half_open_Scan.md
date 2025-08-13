# TCP Half-Open (SYN) Scan

## Definition

A TCP Half-Open scan, also known as a SYN scan, is a stealthy port scanning technique that sends SYN packets and analyzes responses without completing the TCP handshake.

## How Half-Open Scan Works

### Basic Process:
1. **Scanner** sends a TCP SYN packet to the target port.
2. **Target** responds with:
   - **SYN/ACK** if port is open.
   - **RST** if port is closed.
3. If SYN/ACK is received, scanner sends an **RST** instead of ACK, avoiding full connection.

## Tools and Commands

### Nmap SYN Scan
```bash
sudo nmap -sS target_ip

# Specific ports
sudo nmap -sS -p 22,80,443 target_ip

# Verbose mode
sudo nmap -sS -v target_ip
```

## Advantages
- Stealthier than TCP connect scans.
- Faster scanning.
- Avoids full handshake logging in some cases.

## Limitations
- Requires root/admin privileges.
- Still detectable by modern IDS.
- May be blocked by firewalls.

## Detection and Response

### Detection Methods:
- IDS alerts for half-open connections.
- SYN packet flood detection.

### Response Analysis:
```
SYN → SYN/ACK → RST
Port open
```
```
SYN → RST
Port closed
```

## CEH Exam Focus Points
- Understand `-sS` is SYN/half-open scan.
- Recognize it's stealthier than full connect.
- Requires privileges to craft raw packets.
