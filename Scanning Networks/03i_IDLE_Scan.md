# TCP Idle Scan

## Definition

A TCP Idle scan uses a third-party "zombie" host to perform a stealthy port scan without revealing the attacker's IP address.

## How Idle Scan Works

### Basic Process:
1. Identify idle host with predictable IPID sequence.
2. Send spoofed SYN packets to target using zombie's IP.
3. Infer port state based on zombie's IPID changes.

## Tools and Commands

### Nmap Idle Scan
```bash
sudo nmap -sI zombie_ip target_ip
```

## Advantages
- Extremely stealthy — hides attacker's IP.
- Bypasses some logging mechanisms.

## Limitations
- Requires idle host with predictable IPID.
- Slow and dependent on network conditions.

## Detection and Response

### Detection Methods:
- Monitoring unusual traffic from idle hosts.

## CEH Exam Focus Points
- `-sI` = Idle scan.
- Requires zombie host with predictable IPID increments.
