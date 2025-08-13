# SCTP Cookie Echo Scanning

## Overview
SCTP Cookie Echo Scanning sends a COOKIE-ECHO chunk to determine if an SCTP port is open without completing a full handshake.

## How It Works
- After an INIT-ACK, an SCTP handshake normally sends a COOKIE-ECHO.
- This scan sends COOKIE-ECHO directly to the target.
- Open ports may respond with a COOKIE-ACK.
- Closed ports respond with ABORT.

## Usage (Nmap Example)
```bash
nmap --sctp-cookie-echo <target>
```

## Advantages
- Stealthier than INIT scan because it skips initial handshake.
- Can detect SCTP services without establishing a full session.

## Disadvantages
- SCTP traffic is rare, which might make it stand out.
- Limited to SCTP-enabled systems.

## Detection
- IDS/IPS can flag unsolicited COOKIE-ECHO packets.
- SCTP-specific anomaly detection can catch unusual traffic.
