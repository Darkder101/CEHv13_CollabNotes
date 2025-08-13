# IPv6 Scanning

## Definition

IPv6 scanning identifies live hosts and open ports over IPv6 networks, requiring different techniques than IPv4.

## How IPv6 Scan Works

### Basic Process:
1. Use IPv6 address lists or discovery methods (e.g., ICMPv6).
2. Probe for open services over IPv6.

## Tools and Commands

### Nmap IPv6 Scan
```bash
nmap -6 target_ipv6
```

## Advantages
- Expands scope to IPv6-only hosts.
- Useful in modern networks.

## Limitations
- Huge address space makes blind scanning impractical.
- Relies on address enumeration methods.

## Detection and Response

### Detection Methods:
- Monitoring for unusual IPv6 probe traffic.

## CEH Exam Focus Points
- `-6` = IPv6 scan.
- Requires IPv6-capable tools and addressing.
