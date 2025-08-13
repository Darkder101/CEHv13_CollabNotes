# TCP Connect Scan

## Definition

A TCP Connect scan is a host and port scanning method that uses the full TCP three-way handshake to determine if a port is open. This is the default scanning method in Nmap when no special privileges are required.

## How TCP Connect Scan Works

### Basic Process:
1. **Scanner** sends a TCP SYN packet to the target port.
2. **Target** responds with:
   - **SYN/ACK** if port is open.
   - **RST** if port is closed.
3. If **SYN/ACK** received, scanner sends an **ACK** to complete the handshake, then immediately sends an **RST** to close the connection.
4. Open or closed status is determined based on the response.

### Packet Behavior:
- Uses OS-level connect() call.
- Requires completion of TCP handshake.

## Tools and Commands

### Nmap TCP Connect Scan
```bash
nmap -sT target_ip

# Scan specific ports
nmap -sT -p 22,80,443 target_ip

# Verbose mode
nmap -sT -v target_ip

# Multiple targets
nmap -sT 192.168.1.0/24
```

## Advantages
- Works without special privileges.
- Supported on all operating systems.
- Reliable detection of open/closed ports.

## Limitations
- Noisy — easily logged and detected.
- Slower than half-open scanning.
- Completes full handshake, making it less stealthy.

## Detection and Response

### Detection Methods:
- Firewall/IDS logs showing completed handshakes from unknown hosts.
- Unusual volume of connection attempts.

### Response Analysis:
```
SYN → SYN/ACK → ACK → RST
Port open
```
```
SYN → RST
Port closed
```

## CEH Exam Focus Points
- Understand that `-sT` performs full TCP connect scans.
- Recognize handshake completion means less stealth.
- Know differences between connect scan and half-open scan.
