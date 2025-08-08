# Explain Network-Level Session Hijacking & Countermeasures

## Network-Level Session Hijacking

### a. Blind Hijacking
Injecting commands without seeing the response.

### b. UDP Hijacking
Taking over a UDP session by injecting packets.

### c. TCP/IP Hijacking
Manipulating TCP sequence numbers to inject data.

### d. RST Hijacking
Sending forged TCP reset packets to disrupt connections.

### e. Man-in-the-Middle: Packet Sniffer
Capturing packets to steal session info.

### f. IP Spoofing: Source Routed Packets
Faking IP address in packets to hijack sessions.

### g. ARP Spoofing
Faking ARP messages to redirect traffic.

### h. PetitPotam Hijacking
NTLM relay attack targeting Windows environments.

### i. Session Hijacking Tools
- Hetty
- Caido
- Bettercap
- Burp Suite
- OWASP ZAP
- SSLstrip
- Jhijack
- Websploit Framework

## Session Hijacking Countermeasures

### a. Detection Methods
#### i. Manual Method
- Forced ARP entry

#### ii. Automatic Method
- IDS (Intrusion Detection System)
- IPS (Intrusion Prevention System)

### b. Protecting Against Session Hijacking
- Use HTTPS
- Strong session tokens
- Re-generate tokens on login

### c. Web Development Guidelines
- Secure cookies (HttpOnly, Secure)
- Implement logout features

### e. Detection Tools
- USM Anywhere
- Wireshark

### f. Approaches to Prevent Session Hijacking
- HSTS
- Token binding

### g. Approaches to Prevent MITM Attacks
- DNS over HTTPS
- WPA3 encryption
- VPN
- 2FA
- Password manager
- Zero-trust policies
- PKI
- Network segmentation

### h. IPsec
#### i. Modes
- Transport Mode
- Tunnel Mode

#### ii. Architecture
- Authentication Header (AH)
- Encapsulating Security Payload (ESP)
- Domain of Interpretation (DOI)
- Internet Security Association and Key Management Protocol (ISAKMP)
