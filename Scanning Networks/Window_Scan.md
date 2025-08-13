# TCP Window Scan

## Definition

A TCP Window scan analyzes the TCP Window field in responses to detect open ports.

## How Window Scan Works

### Basic Process:
1. Scanner sends ACK packet to target port.
2. Open ports may have a non-zero TCP Window size.
3. Closed ports usually have a zero window size.

## Tools and Commands

### Nmap Window Scan
```bash
sudo nmap -sW target_ip
```

## Advantages
- Stealthier than SYN scans.
- Exploits subtle TCP stack behavior.

## Limitations
- OS dependent behavior.
- Less reliable on modern systems.

## Detection and Response

### Detection Methods:
- Monitoring for ACK probes without established connections.

## CEH Exam Focus Points
- `-sW` = TCP Window scan.
- Relies on TCP Window size differences.
