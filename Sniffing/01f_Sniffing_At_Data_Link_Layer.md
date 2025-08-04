## Sniffing in the Data Link Layer (Layer 2)

### 🔹 Key Concepts

- Operates at **Layer 2 (Data Link Layer)** of the OSI model
- Captures **Ethernet frames**, including:
  - **MAC addresses**
  - **Frame headers**
  - **Payload (data)**

### 🔹 How Sniffing Works at Layer 2

- **NIC in promiscuous mode** intercepts all frames on the segment
- Works best in networks with **hubs or broadcast-based communication**
- Switches restrict visibility using **CAM tables**

---

### 🔹 CAM Table Limitation

- **Switches** use **Content Addressable Memory (CAM)** to map MAC addresses to ports
- Packets are only forwarded to the correct port — sniffers can't see others' traffic
- **CAM Table Attacks**:
  - **MAC Flooding** fills the CAM table
  - Switch acts like a hub → enables sniffing

---

### 🔹 Common Attacks at Layer 2

- MAC Flooding
- ARP Spoofing
- Switch Port Stealing
- VLAN Hopping

> Layer 2 sniffing requires bypassing switch limitations. Expect questions on CAM tables and MAC flooding.

---
