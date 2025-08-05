## Switch Port Stealing

### 🔹 What Is It?

- **Switch Port Stealing (SPS)** is an attack that allows an attacker to **hijack** the port of a legitimate user by exploiting **MAC address learning** on a switch.

---

### 🔹 How It Works

1. Attacker sends **spoofed ARP packets** claiming to be the victim (legitimate host).
2. Switch updates its **CAM table**, associating the victim’s MAC with the **attacker’s port**.
3. Legitimate user replies → Switch updates again.
4. Repeated spoofing causes the CAM table to **flip-flop**, creating a race condition.
5. During a successful "steal," attacker receives traffic meant for the victim.

---

### 🔹 Goal of the Attack

- **Intermittently intercept packets** destined for a specific host on the network.
- Enables **partial packet sniffing** or **session hijacking**.

---

### 🔹 Tools Used

- `Yersinia`
- Custom ARP spoofing scripts (e.g., Scapy)

---

### 🔹 Detection Methods

- Frequent CAM table updates for the same MAC
- ARP cache inconsistencies
- Switch logs showing **MAC address flapping**

---

### 🔹 Defense Mechanisms

| Defense                         | Description                                 |
|---------------------------------|---------------------------------------------|
| **Port Security**               | Bind specific MACs to specific ports        |
| **Dynamic ARP Inspection (DAI)**| Blocks invalid ARP replies                  |
| **DHCP Snooping**               | Works with DAI to verify IP/MAC bindings    |
| **ARP Watch Tools**             | Monitor ARP changes                         |

> SPS doesn't flood the switch like MAC Flooding — it targets specific hosts. Know the difference between hijacking vs. general broadcast sniffing.

---
