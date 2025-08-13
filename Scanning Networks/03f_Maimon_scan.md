# TCP Maimon Scan

## Definition

The TCP Maimon scan, discovered by Uriel Maimon, sends FIN/ACK packets to detect open ports in a stealthy way.

## How Maimon Scan Works

### Basic Process:
1. Scanner sends packet with FIN and ACK flags set.
2. Open ports drop the packet.
3. Closed ports respond with RST.

## Tools and Commands

### Nmap Maimon Scan
```bash
sudo nmap -sM target_ip

# Specific ports
sudo nmap -sM -p 22,80,443 target_ip
```

## Advantages
- Stealthy against certain IDS/firewall setups.
- Less common, so less likely to be filtered.

## Limitations
- Limited support on some systems.
- May be blocked by modern firewalls.

## Detection and Response

### Detection Methods:
- IDS monitoring for FIN/ACK packet patterns.

### Response Analysis:
```
No response → Port open/filtered
RST → Port closed
```

## CEH Exam Focus Points
- `-sM` = Maimon scan.
- Relies on FIN/ACK behavior.
- Named after Uriel Maimon.
