# Summarize Session Hijacking Concepts

## a. What is Session Hijacking
Session Hijacking is a cyberattack where an attacker takes over a valid session between a client and server to gain unauthorized access to resources or data.

## b. Why is Session Hijacking Successful
- Poor session management
- Weak encryption
- Predictable session IDs
- Insecure network communications (HTTP instead of HTTPS)

## c. Session Hijacking Process
1. Identify active session
2. Steal or predict session ID
3. Impersonate the legitimate user

## d. Packet Analysis of a Local Session Hijack
- Capturing packets using sniffers (e.g., Wireshark, tcpdump)
- Extracting session IDs/cookies
- Replaying the session

## e. Types of Session Hijacking
### i. Passive Session Hijacking
- Eavesdropping without interfering
- Typically used for data gathering

### ii. Active Session Hijacking
- Taking control of an active session
- Injecting commands/data

## f. Session Hijacking in OSI Model
### i. Network Level
- Targeting network communication (TCP/IP)
- Examples: ARP spoofing, IP spoofing

### ii. Application Level
- Targeting session tokens/cookies in apps
- Examples: XSS, CSRF

## g. Spoofing vs Hijacking
- **Spoofing**: Pretending to be someone else without taking control of their session
- **Hijacking**: Taking over an existing active session
