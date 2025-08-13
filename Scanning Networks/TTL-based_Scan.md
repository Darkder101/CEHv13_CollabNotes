# TTL-Based Scan

## Definition

A TTL-based scan uses variations in Time-To-Live (TTL) values in received packets to infer whether a host or port is open, closed, or filtered.

## How TTL-Based Scan Works

### Basic Process:
1. Scanner sends probe packets to target.
2. Analyzes TTL values in responses.
3. Differences in TTL may indicate different systems or states.

## Tools and Commands

### Nmap Example
```bash
nmap --ttl 64 target_ip
```

## Advantages
- Can help fingerprint operating systems.
- May detect filtered ports indirectly.

## Limitations
- Requires analysis of TTL patterns.
- TTL can be altered by intermediate devices.

## Detection and Response

### Detection Methods:
- Monitoring for unusual TTL probe patterns.

## CEH Exam Focus Points
- TTL variations can hint at OS type or network hops.
- Useful for indirect discovery and evasion.
