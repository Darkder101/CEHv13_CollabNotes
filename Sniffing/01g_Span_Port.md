## SPAN Port (Switched Port Analyzer)

### 🔹 What is a SPAN Port?

- A **monitoring port** on a switch that **mirrors traffic** from one or more ports/VLANs to another port
- Used to analyze network traffic **without disrupting** the network

### 🔹 Purpose

- **Traffic analysis** and **packet capturing** using sniffers like Wireshark
- Commonly used by:
  - Network admins (legit monitoring)
  - Attackers with access (for sniffing in switched environments)

---

### 🔹 Types of SPAN

| Type         | Description                                |
|--------------|--------------------------------------------|
| **Local SPAN** | Source and destination on same switch     |
| **RSPAN**      | Remote SPAN, uses VLAN to send mirrored data across switches |
| **ERSPAN**     | Encapsulated RSPAN over IP network, includes headers for remote analysis |

---

### 🔹 Security Considerations

- SPAN is **read-only**: Cannot inject traffic
- Requires **admin-level access** to configure
- **Misconfigured SPAN ports** can leak sensitive data

---

### 🔹 CEH Focus Points

- Used in **switched networks** for visibility
- SPAN ports help sniff traffic **without flooding the switch**
- Know **types** and **use cases** (e.g., SPAN vs. MAC flooding)

> SPAN ports are legit tools, but attackers with access can misuse them. Expect questions comparing SPAN with sniffing attacks like MAC flooding.

---
