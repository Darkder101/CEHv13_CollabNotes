## Rogue DHCP Server Attack

### 🔹 What Is It?

- A **malicious DHCP server** is introduced into the network to **issue fake IP configuration** to clients.

---

### 🔹 How It Works

1. Attacker sets up a **rogue DHCP server** on the network.
2. Victim device sends a DHCPDISCOVER broadcast.
3. **Both legitimate and rogue DHCP servers** respond.
4. If the client accepts the rogue offer:
   - Attacker can assign:
     - **Fake gateway** (for MITM)
     - **Malicious DNS** (for DNS spoofing)
     - **Wrong IP configuration** (for DoS)

---

### 🔹 Goal of the Attack

- Redirect user traffic through attacker-controlled devices.
- Launch further attacks:
  - **MITM**
  - **Sniffing**
  - **DNS poisoning**

---

### 🔹 Tools Used

- `Yersinia`
- `Rogue DHCP Server` tools (e.g., Kali Linux DHCP config)
- Custom DHCP scripts

---

### 🔹 Detection Methods

- Multiple DHCP servers responding
- Unexpected default gateways or DNS settings on clients
- DHCP logs and alerts

---

### 🔹 Defense Mechanisms

| Defense                  | Description                                     |
|--------------------------|-------------------------------------------------|
| **DHCP Snooping**        | Allows DHCP responses only from trusted ports   |
| **Switch Port Security** | Blocks unauthorized devices                     |
| **Monitor DHCP Traffic** | Look for unauthorized DHCP OFFER messages       |

> This attack often follows DHCP Starvation. Know how DHCP Snooping blocks both starvation and rogue server attacks by validating ports and MAC bindings.
