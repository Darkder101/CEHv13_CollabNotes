## Types of Sniffing

### 🔹 1. Passive Sniffing
- **Listens silently** to network traffic
- Works on **hubs** and **wireless networks**
- **Hard to detect**
- Captures broadcast/multicast traffic without altering data flow

### 🔹 2. Active Sniffing
- **Injects traffic** or manipulates network behavior to intercept data
- Required on **switched networks**
- **Easier to detect** due to abnormal behavior
- Common attack techniques:
  - ARP Spoofing
  - MAC Flooding
  - DHCP Starvation
  - DNS Poisoning
  - Switch Port Stealing
  - Spoofing-based attacks (MAC/IP/DNS/ARP)

---

### 🔹 Key Differences

| Feature            | Passive Sniffing        | Active Sniffing           |
|--------------------|--------------------------|----------------------------|
| Works On           | Hubs / Wi-Fi             | Switches                  |
| Stealth            | High (Hard to detect)    | Low (Detectable)          |
| Traffic Injection  | ❌ No                    | ✅ Yes                    |
| Common Use         | Monitoring               | Attacking / Switch Bypass |

---

### 🔹 Protocols Vulnerable to Spoofing

- ❌ **Unencrypted protocols** are most at risk:
  - HTTP
  - FTP
  - Telnet
  - POP3
  - SMTP
  - SNMP v1/v2
  - DNS
  - ARP

- ✅ Use secure versions where available:
  - HTTPS, SFTP, SSH, SNMPv3
---
