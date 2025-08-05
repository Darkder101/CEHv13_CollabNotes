## DHCP Starvation Attack

### 🔹 What Is It?

- An attack that **exhausts the IP address pool** of a DHCP server by sending **numerous fake DHCP requests**.

---

### 🔹 How It Works

1. Attacker sends **hundreds or thousands of DHCP requests** with **spoofed MAC addresses**.
2. DHCP server assigns IP addresses to each fake request.
3. Eventually, the **IP pool is exhausted**.
4. **Legitimate clients** cannot get an IP and **lose network access**.

---

### 🔹 Goal of the Attack

- **Denial of Service (DoS)** for valid users  
- Prepare for **Rogue DHCP Server** attack

---

### 🔹 Tools Used

- `Yersinia`
- `dhcpstarv`
- `Gobuster` (with scripts)

---

### 🔹 Detection Methods

- High volume of DHCPDISCOVER messages
- Many IPs assigned to unknown MACs
- DHCP server logs

---

### 🔹 Defense Mechanisms

| Defense           | Description                                   |
|-------------------|-----------------------------------------------|
| **DHCP Snooping** | Allows only trusted ports to respond to DHCP  |
| **Rate Limiting** | Limits DHCP requests per port                 |
| **Port Security** | Restricts number of MAC addresses per port    |

> DHCP Starvation is often a **precursor to Rogue DHCP** attacks. Know how attackers disrupt IP assignment to gain control over the network.
