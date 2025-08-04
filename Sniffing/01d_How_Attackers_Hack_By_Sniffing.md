## How an Attacker Hacks Network Using Sniffers

### 🔹 Attack Workflow

1. **Reconnaissance**  
   - Identify active devices, open ports, and protocols.

2. **Network Access**  
   - Gain access to the same network segment (wired/wireless).

3. **Deploy Sniffing Tools**  
   - Tools like `Wireshark`, `tcpdump`, `Ettercap`, or custom sniffers.

4. **Capture Traffic**  
   - Use **promiscuous mode** to intercept data on the wire.

5. **Extract Sensitive Data**  
   - Credentials (FTP, Telnet, POP3)  
   - Session tokens  
   - Emails, HTTP requests, internal IPs

---

### 🔹 Common Targets

- **Login credentials** (plain-text protocols)
- **Session hijacking** data (cookies, tokens)
- **Clear-text communications**
- **Internal IP schema and topologies**

---

### 🔹 Tools Used

| Tool       | Purpose                         |
|------------|----------------------------------|
| Wireshark  | GUI-based packet analyzer        |
| tcpdump    | CLI sniffer for live traffic     |
| Ettercap   | Sniffing + MITM + ARP spoofing   |
| Cain & Abel | Sniffing + credential cracking  |

---
