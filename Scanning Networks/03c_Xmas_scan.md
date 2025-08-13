# TCP Xmas Scan

## Definition

A TCP Xmas scan is a stealthy port scanning technique that sends TCP packets with the FIN, PSH, and URG flags set, lighting up the packet "like a Christmas tree."

## How Xmas Scan Works

### Basic Process:
1. Scanner sends packet with FIN, PSH, URG flags set.
2. RFC 793 specifies:
   - Closed ports respond with RST.
   - Open ports drop packet (no response).

## Tools and Commands

### Nmap Xmas Scan
```bash
sudo nmap -sX target_ip

# Specific ports
sudo nmap -sX -p 22,80,443 target_ip
```

## Advantages
- Can bypass some firewalls and packet filters.
- Stealthy — open ports give no reply.

## Limitations
- Only works reliably on UNIX/Linux systems (Windows ignores these packets).
- Firewalls may drop such packets.
- Cannot detect open ports on all systems.

## Detection and Response

### Detection Methods:
- IDS alerts for unusual TCP flag combinations.

### Response Analysis:
```
No response → Port open/filtered
RST → Port closed
```

## CEH Exam Focus Points
- `-sX` = Xmas scan.
- Relies on RFC 793 behavior.
- Limited effectiveness on Windows targets.
