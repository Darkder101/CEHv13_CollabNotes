# Explain Network-Level Session Hijacking & Countermeasures

Network-level hijacking focuses on **transport layer sessions** (TCP, UDP) and involves packet injection, interception, or manipulation.

---

## 🔹 Types of Network-Level Session Hijacking

### a. Blind Hijacking
- Inject malicious commands without seeing responses.
- Requires guessing sequence numbers.
- Example: Sending “delete all logs” command to server session.

### b. UDP Hijacking
- Spoof UDP packets (easy because connectionless).
- Used in VoIP call takeovers.

### c. TCP/IP Hijacking
- Predict sequence numbers → inject data into TCP stream.

### d. RST Hijacking
- Send forged TCP Reset packets to close a session.

### e. MITM via Packet Sniffer
- Capture all packets → extract session credentials.

### f. IP Spoofing (Source Routed Packets)
- Fake source IP in packets → redirect responses.

### g. ARP Spoofing
- Poison ARP cache to map attacker’s MAC to victim’s IP.

### h. PetitPotam Hijacking
- NTLM relay attack targeting Windows domain controllers.

---

## 🔹 Tools Used

- Hetty
- Caido
- Bettercap
- Burp Suite
- OWASP ZAP
- SSLstrip
- Jhijack
- Websploit Framework

---

## 🔹 Countermeasures

### Detection
- **Manual**: Force static ARP entries.
- **Automatic**: IDS (detect anomalies), IPS (block).

---

### Prevention
- Always use HTTPS/TLS.
- Short session expiry.
- Regenerate tokens often.
- Use **HSTS** to enforce HTTPS.
- Token Binding → bind token to TLS layer.

---

### Preventing MITM
- DNS over HTTPS.
- WPA3 encryption.
- VPN.
- Two-Factor Authentication.
- Password Managers.
- Zero-trust policies.
- PKI infrastructure.
- Network segmentation.

---

### IPsec

**Modes**:
- **Transport Mode**: Encrypts only payload.
- **Tunnel Mode**: Encrypts full packet.

**Architecture**:
- Authentication Header (AH)
- Encapsulating Security Payload (ESP)
- Domain of Interpretation (DOI)
- ISAKMP
- Security Policy

---

## Quick Tip for CEH Exam (with explanations):

- **Blind Hijacking** = send commands without seeing response.
- **RST Hijacking** = forcibly reset connection.
- **PetitPotam** = NTLM relay attack.
- **IPsec Modes** = Transport = payload only, Tunnel = header + payload.
- **Tools**: Expect Bettercap, Burp Suite, SSLstrip as answer options.
