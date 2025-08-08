# Session Hijacking - Last Night Revision

## Key Points
- **Definition**: Taking over an active session between client & server.
- **Why it works**: Weak tokens, unencrypted traffic, predictable IDs.
- **Types**: Passive (listen), Active (take over).
- **Levels**: Network (TCP/IP), Application (cookies/tokens).

## Quick Attack Examples
- **App Level**: XSS, CSRF, Session Fixation, Replay.
- **Net Level**: ARP Spoofing, TCP hijack, MITM.

## Prevention
- HTTPS, Secure cookies, IDS/IPS, 2FA, Token regeneration, IPsec.

## Predictable CEH Questions
Q: Difference between spoofing & hijacking?  
A: Spoofing = pretending, Hijacking = taking over.

Q: Example of network-level attack?  
A: TCP/IP hijacking.

Q: Tool for session hijacking?  
A: Bettercap, Burp Suite.
