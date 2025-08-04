## How a Sniffer Works

### 🔹 Core Workflow
1. **NIC enters Promiscuous Mode**
2. Captures **all packets** on the network segment
3. Forwards packets to the **sniffer application** (e.g., Wireshark)
4. Analyst or attacker **inspects captured traffic**

### 🔹 NIC Modes
- **Normal Mode**: Captures packets only **addressed to its MAC**
- **Promiscuous Mode**: Captures **all broadcast and unicast** traffic on the network

### 🔹 OSI Model Level
- Operates at **Layer 2 (Data Link Layer)**
- Can see Ethernet frames, MAC addresses, and payload

### 🔹 Requirements
- Works **passively** on hubs and Wi-Fi
- Needs **active sniffing techniques** on switches (e.g., ARP poisoning, MAC flooding)

### 🔹 Tools That Use This
- `Wireshark`, `tcpdump`, `Ettercap`, `Kismet`

> 🧠 **CEH Tip**: Remember – Sniffers don’t alter traffic; they just **observe** it. But enabling promiscuous mode is essential to capture beyond the host’s traffic.

---
