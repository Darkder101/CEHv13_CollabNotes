# SCTP INIT Scanning

## Overview
SCTP INIT Scanning is a technique that sends an INIT chunk to the target's SCTP port to check whether the port is open.

## How It Works
- SCTP (Stream Control Transmission Protocol) is used in certain telecom and specialized network systems.
- The scanner sends an INIT packet to the target SCTP port.
- If the port is open, the target responds with an INIT-ACK.
- If closed, the target responds with an ABORT.

## Usage (Nmap Example)
```bash
nmap --sctp-init <target>
```

## Advantages
- Works well for SCTP-based services.
- Can identify open and closed ports reliably.

## Disadvantages
- Less common than TCP/UDP scans, so limited applicability.
- May be blocked by firewalls unfamiliar with SCTP traffic.

## Detection
- Network monitoring tools can detect INIT packets.
- Unusual traffic on SCTP ports may trigger alerts.
