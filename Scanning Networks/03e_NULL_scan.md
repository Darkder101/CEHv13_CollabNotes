# TCP NULL Scan

## Definition

A TCP NULL scan sends packets with no flags set to test target port behavior.

## How NULL Scan Works

### Basic Process:
1. Scanner sends TCP packet with no flags set.
2. RFC 793 specifies:
   - Closed ports respond with RST.
   - Open ports drop packet.

## Tools and Commands

### Nmap NULL Scan
```bash
sudo nmap -sN target_ip

# Specific ports
sudo nmap -sN -p 22,80,443 target_ip
```

## Advantages
- Can bypass some filtering systems.
- Simple to execute.

## Limitations
- Ineffective on Windows (RST for all ports).
- May trigger IDS alerts.

## Detection and Response

### Detection Methods:
- IDS alerts for TCP packets with no flags.

### Response Analysis:
```
No response → Port open/filtered
RST → Port closed
```

## CEH Exam Focus Points
- `-sN` = NULL scan.
- Relies on RFC 793 open/closed port response behavior.
- Limited on Windows systems.
