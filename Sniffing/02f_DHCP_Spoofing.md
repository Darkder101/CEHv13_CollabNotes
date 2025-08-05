## DHCP Spoofing & Dynamic ARP Inspection (DAI)

---

## 🔹 What Is DHCP Spoofing?

- An attacker sets up a **fake DHCP server** to assign malicious configurations (IP, gateway, DNS) to clients.
- Used for:
  - **MITM**
  - **Traffic redirection**
  - **Denial of service**

---

## 🔹 What Is Dynamic ARP Inspection (DAI)?

- A **Layer 2 security feature** that blocks **invalid or spoofed ARP packets**.
- DAI uses **trusted/untrusted port logic** and **DHCP snooping bindings** to verify ARP traffic.

---

## 🔹 How They Work Together

1. **DHCP Snooping** builds a binding table of:
   - MAC address  
   - IP address  
   - Port number  
2. **DAI** uses this table to check:
   - Is the ARP packet valid?
   - Does MAC-IP mapping match the table?
3. Invalid ARP replies = **blocked**

---

## 🔹 Key Configuration Concepts

| Feature            | Purpose                                        |
|--------------------|------------------------------------------------|
| **Trusted Ports**   | Allow legitimate DHCP/ARP traffic              |
| **Untrusted Ports** | Block spoofed or rogue replies                 |
| **Binding Table**   | Stores IP-MAC-port mappings from DHCP snooping |

---

## 🔹 Defense Capabilities

- **Prevents**:
  - ARP spoofing
  - DHCP starvation
  - Rogue DHCP attacks  
- **Ensures**:
  - Only valid IP-MAC-port mappings are allowed
  - ARP traffic integrity

---

## 🔹 CEH Focus Points

- DHCP Snooping and DAI must be **enabled on switches**
- Works only in networks using **DHCP**
- DAI doesn’t work on **static IP environments**
- Part of **Layer 2 hardening**

> Expect scenario-based questions asking how to prevent ARP spoofing or rogue DHCP. Answer = Enable DHCP Snooping + DAI.
