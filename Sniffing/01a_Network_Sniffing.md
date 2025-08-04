## Network Sniffing

### 🔹 Definition
- The process of **monitoring and capturing network packets** as they travel over a network.

### 🔹 Purpose
- **Legitimate**: Network troubleshooting and performance analysis  
- **Malicious**: Intercept sensitive data (e.g., credentials, session tokens)

### 🔹 How It Works
- Requires placing the **Network Interface Card (NIC)** in **promiscuous mode**
- Promiscuous mode = NIC captures **all packets**, not just those addressed to it

### 🔹 Key Exam Points
- Works at **OSI Layer 2** (Data Link Layer)
- Used in both **passive** and **active** sniffing techniques
- Common tools: `Wireshark`, `tcpdump`, `Ettercap`
- Crucial for attacks like:
  - Password interception
  - Session hijacking
  - ARP/DNS spoofing

> ⚠️ *Know the difference between passive (hub/wireless) and active (switch) sniffing in context of NIC behavior and network design.*

---
