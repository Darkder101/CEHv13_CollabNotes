# 📌 Common Ports and Protocols – CEH v13 Exam Reference
---

## 🔹 Common TCP/UDP Ports & Protocols

| Port | Protocol | Transport | Description | Common Attacks / Tools |
|------|----------|-----------|-------------|------------------------|
| **20** | FTP Data | TCP | Transfers files (active mode) | Brute force, sniffing (Wireshark) |
| **21** | FTP Control | TCP | Controls file transfers | Hydra, Medusa, Brute force |
| **22** | SSH | TCP | Secure remote login | Hydra, key cracking |
| **23** | Telnet | TCP | Unencrypted remote login | Banner grabbing, sniffing |
| **25** | SMTP | TCP | Send emails | Mail spoofing, phishing |
| **53** | DNS | TCP/UDP | Domain name resolution | DNS poisoning, dnsrecon |
| **67/68** | DHCP | UDP | Auto IP assignment | Rogue DHCP attacks |
| **69** | TFTP | UDP | Trivial file transfer | Config file theft |
| **80** | HTTP | TCP | Web browsing | SQLi, XSS, BurpSuite |
| **110** | POP3 | TCP | Receive email | Email sniffing |
| **111** | RPCbind | TCP/UDP | Remote procedure calls | RPC enumeration |
| **119** | NNTP | TCP | Usenet news | Rare exam use |
| **123** | NTP | UDP | Time sync | NTP amplification |
| **135** | MS RPC | TCP | Windows services | DCOM exploitation |
| **137-139** | NetBIOS | TCP/UDP | Windows file/printer sharing | enum4linux, SMB attacks |
| **143** | IMAP | TCP | Email retrieval | Email interception |
| **161/162** | SNMP | UDP | Network device management | snmpwalk, SNMP brute force |
| **179** | BGP | TCP | Border gateway routing | BGP hijacking |
| **389** | LDAP | TCP/UDP | Directory services | LDAP injection |
| **443** | HTTPS | TCP | Secure web traffic | SSL stripping |
| **445** | SMB | TCP | Windows file sharing | EternalBlue, SMB relay |
| **500** | ISAKMP | UDP | VPN key exchange | VPN MITM attacks |
| **514** | Syslog | UDP | Logging service | Log injection |
| **520** | RIP | UDP | Routing protocol | Route poisoning |
| **546/547** | DHCPv6 | UDP | IPv6 DHCP | Rogue DHCPv6 attacks |
| **587** | SMTP (Submission) | TCP | Email sending | Mail relay abuse |
| **631** | IPP | TCP/UDP | Printing | Printer exploitation |
| **993** | IMAPS | TCP | Secure IMAP | Email MITM |
| **995** | POP3S | TCP | Secure POP3 | Email MITM |
| **1433** | MS SQL Server | TCP | Database server | SQL brute force |
| **1521** | Oracle DB | TCP | Oracle database | SQL injection |
| **2049** | NFS | TCP/UDP | File system sharing | File theft |
| **3306** | MySQL | TCP | Database server | SQL injection, brute force |
| **3389** | RDP | TCP | Remote desktop | Hydra, RDP brute force |
| **5432** | PostgreSQL | TCP | Database server | SQL injection |
| **5900** | VNC | TCP | Remote desktop | Password brute force |
| **5985/5986** | WinRM | TCP | Windows Remote Management | Lateral movement |
| **8000/8080** | HTTP Alt | TCP | Proxy/web server | Web scanning |
| **8443** | HTTPS Alt | TCP | Secure web service | Web pentest |
| **9000** | SonarQube / Alt | TCP | Code quality server | Rare in CEH |
| **9050/9051** | Tor SOCKS | TCP | Tor traffic | Onion routing |
| **10000** | Webmin | TCP | Web admin panel | Panel exploitation |

---
