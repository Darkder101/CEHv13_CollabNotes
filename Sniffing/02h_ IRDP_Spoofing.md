## ICMP Router Discovery Protocol (IRDP) Spoofing

---

### 🔹 What Is It?

- **IRDP Spoofing** is an attack where fake ICMP Router Advertisement messages are sent to **trick hosts** into using a **malicious default gateway**.
- Exploits **ICMP Type 9/10** (Router Advertisement/Solicitation).

---

### 🔹 How It Works

1. Host sends ICMP Router Solicitation (Type 10) or waits for Router Advertisements (Type 9).
2. Attacker sends **fake Router Advertisement** with:
   - Malicious IP as default gateway.
3. Host updates its routing table → forwards traffic to attacker.
4. Attacker performs **MITM** or **traffic manipulation**.

---

### 🔹 Goal of the Attack

- Redirect traffic to attacker-controlled gateway.
- Enables:
  - **Sniffing**
  - **MITM**
  - **Traffic manipulation or blocking**

---

### 🔹 Tools Used

- Custom crafted packets using:
  - `Scapy`
  - `Nemesis`
- Some legacy systems vulnerable by default

---

### 🔹 Detection Methods

- Unexpected router entries in routing tables
- Sniffing for **suspicious ICMP Type 9** messages
- ICMP monitoring tools

---

### 🔹 Defense Mechanisms

| Defense                 | Description                                      |
|-------------------------|--------------------------------------------------|
| **Disable IRDP**        | On clients and routers (default off on many systems) |
| **Use Static Gateways** | Prevent automatic route changes                  |
| **ICMP Filtering**      | Block unsolicited ICMP Type 9 traffic            |

> IRDP spoofing is less common today but still testable. Know it’s about **default gateway manipulation using ICMP**, not ARP or DHCP.
