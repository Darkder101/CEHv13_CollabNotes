# TCP FIN Scan

## Definition

A TCP FIN scan sends packets with only the FIN flag set to identify open ports without establishing a connection.

## How FIN Scan Works

### Basic Process:
1. Scanner sends packet with FIN flag to target port.
2. RFC 793 specifies:
   - Closed ports respond with RST.
   - Open ports ignore packet.

## Tools and Commands

### Nmap FIN Scan
```bash
sudo nmap -sF target_ip

# Specific ports
sudo nmap -sF -p 22,80,443 target_ip
```

## Advantages
- Can bypass some filtering devices.
- Stealthier than SYN scans.

## Limitations
- Ineffective against Windows targets (they send RST regardless).
- Firewalls may block these packets.

## Detection and Response

### Detection Methods:
- IDS signatures for FIN flag only packets.

### Response Analysis:
```
No response → Port open/filtered
RST → Port closed
```

## CEH Exam Focus Points
- `-sF` = FIN scan.
- Based on RFC 793 behavior.
- Limited on Windows systems.
