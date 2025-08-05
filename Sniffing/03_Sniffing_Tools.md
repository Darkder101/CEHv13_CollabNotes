## Objective: Understand and utilize common **sniffing tools** for network analysis, attack simulation, and defense validation.

---

## 🔹 Overview

- Sniffing tools capture and analyze packets traversing the network.
- Useful for:
  - **Network troubleshooting**
  - **Identifying vulnerabilities**
  - **Performing MITM/sniffing attacks (for red teaming)**
  - **Detecting unauthorized traffic**
- Operate best in **promiscuous mode** to capture all packets within network scope.

---

## 🔹 3a. Wireshark

- **Most widely-used network protocol analyzer.**
- Allows packet-level inspection of:
  - HTTP, FTP, SMTP, ARP, DHCP, DNS, etc.
- Use cases:
  - Reconstruct sessions
  - Identify suspicious traffic
  - Visualize ARP spoofing/DHCP starvation attacks
- Filters:
  - Capture: `tcp port 80`, `udp port 53`, `arp`
  - Display: `ip.addr == 192.168.1.5 && tcp`
- Supports live capture and offline analysis.

✅ *Next: Detailed note on Wireshark use, filters, examples, and exam tips.*

---

## 🔹 3b. Different Sniffing Tools

| Tool            | Description                                            | OS Support     |
|-----------------|--------------------------------------------------------|----------------|
| **tcpdump**     | CLI-based packet sniffer; ideal for scripting/logging | Linux, macOS   |
| **Ettercap**    | MITM tool; supports ARP poisoning and sniffing        | Cross-platform |
| **Cain & Abel** | Legacy tool with sniffing, spoofing, cracking modules | Windows        |
| **dsniff**      | Collection of sniffing tools (e.g., `arpspoof`, `filesnarf`) | Linux |
| **NetworkMiner**| Forensic analysis & session reconstruction GUI tool   | Windows        |
| **Ngrep**       | Like grep, but for network traffic                    | Linux, Unix    |
| **Snort**       | IDS/IPS tool; detects sniffing and other anomalies     | Cross-platform |
| **MITMf**       | Powerful MITM framework supporting plugin-based attacks| Linux          |

---

## 🔹 CEH Tip

> Remember: Many sniffing tools are dual-purpose — used by attackers for exploitation and by defenders for forensic investigation and detection.
