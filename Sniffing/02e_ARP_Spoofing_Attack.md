## ARP Spoofing Attack

### 🔹 What Is It?

- An attack where the attacker sends **fake ARP replies** to associate their MAC address with another device’s IP (usually the gateway or victim).
- Also known as **ARP Poisoning**.

---

### 🔹 How It Works

1. Attacker sends **spoofed ARP responses** on the local network.
2. Victim updates its ARP cache with attacker’s MAC for a trusted IP (e.g., gateway).
3. Now, victim’s traffic intended for the gateway is sent to the attacker.
4. Attacker can **intercept, modify, or drop** traffic.

---

### 🔹 Goal of the Attack

- Perform **Man-in-the-Middle (MITM)**
- Intercept sensitive data (e.g., credentials, cookies)
- Redirect or disrupt traffic

---

### 🔹 Tools Used

- `Ettercap`
- `Cain & Abel`
- `arpspoof` (part of dsniff)
- `Bettercap`

---

### 🔹 Detection Methods

- Duplicate IP-MAC mappings in ARP cache
- ARP traffic spikes
- Use of detection tools like `XArp`, `ARPwatch`

---

### 🔹 Defense Mechanisms

| Defense                    | Description                                     |
|----------------------------|-------------------------------------------------|
| **Dynamic ARP Inspection** | Blocks invalid or spoofed ARP responses         |
| **Static ARP Entries**     | Manually define MAC-IP mappings                 |
| **DHCP Snooping**          | Works with DAI to validate IP-MAC bindings      |
| **ARP Monitoring Tools**   | Detect suspicious ARP changes (e.g., ARPwatch)  |

> ARP Spoofing works only in local subnet (Layer 2). Be ready for exam questions involving MITM via ARP in switched environments.
