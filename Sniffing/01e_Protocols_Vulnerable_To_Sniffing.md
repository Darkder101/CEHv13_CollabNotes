## Protocols Vulnerable to Sniffing

### 🔹 Insecure (Vulnerable) Protocols

These protocols **transmit data in plaintext**, making them easily sniffable:

| Protocol | Port | Use Case                  |
|----------|------|---------------------------|
| HTTP     | 80   | Web traffic               |
| FTP      | 21   | File transfers            |
| Telnet   | 23   | Remote terminal access    |
| SMTP     | 25   | Email sending             |
| POP3     | 110  | Email receiving           |
| IMAP     | 143  | Email synchronization     |
| SNMP v1/v2 | 161 | Network management        |
| DNS      | 53   | Domain name resolution    |
| TFTP     | 69   | Trivial file transfers    |

> ⚠️ These protocols are easy targets for sniffing and spoofing attacks.

---

### 🔹 Secure Alternatives

| Insecure     | Secure Alternative |
|--------------|--------------------|
| HTTP         | HTTPS (443)        |
| FTP          | SFTP / FTPS        |
| Telnet       | SSH                |
| POP3/IMAP    | POP3S / IMAPS      |
| SNMP v1/v2   | SNMP v3            |
| TFTP         | SCP / SFTP         |

---

### 🔹 CEH Focus Points

- Sniffers extract:
  - **Usernames/passwords**
  - **Session tokens**
  - **Sensitive data**
- Use encrypted protocols to defend against sniffing
- **Unencrypted = unsafe on any shared network**
---
