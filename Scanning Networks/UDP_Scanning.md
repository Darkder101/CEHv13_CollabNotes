# UDP Scanning

## Definition

UDP scanning identifies open UDP ports by sending UDP packets and analyzing responses (or lack thereof).

## How UDP Scan Works

### Basic Process:
1. Send empty or application-specific UDP packets to target ports.
2. Closed ports usually respond with ICMP Port Unreachable.
3. No response often indicates open or filtered.

## Tools and Commands

### Nmap UDP Scan
```bash
sudo nmap -sU target_ip

# Specific ports
sudo nmap -sU -p 53,161 target_ip
```

## Advantages
- Only way to detect open UDP services.
- Useful for finding DNS, SNMP, TFTP services.

## Limitations
- Slow — no handshake, requires timeouts.
- Firewalls may block UDP probes.

## Detection and Response

### Detection Methods:
- Monitoring for UDP probes to multiple ports.

## CEH Exam Focus Points
- `-sU` = UDP scan.
- Open ports often give no reply, closed send ICMP Port Unreachable.
