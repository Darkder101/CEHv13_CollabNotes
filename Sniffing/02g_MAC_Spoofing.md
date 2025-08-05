## MAC Spoofing / Duplicating

---

### 🔹 What Is It?

- **MAC Spoofing** involves changing the **MAC address** of a network interface to **impersonate** another device.
- Also called **MAC duplicating** when mimicking an active host.

---

### 🔹 How It Works

1. Attacker discovers a valid MAC address on the network.
2. They **modify their NIC’s MAC address** to match that of the target.
3. Switch updates CAM table → maps target MAC to attacker’s port.
4. Traffic destined for the target may be:
   - Intercepted  
   - Disrupted  
   - Dropped (conflict)

---

### 🔹 Goals of the Attack

- **Bypass MAC filtering or port security**
- **Impersonate a legitimate user**
- Intercept traffic (limited sniffing opportunity)

---

### 🔹 Tools Used

- `macchanger` (Linux)
- Manual configuration via OS settings
- Custom scripts (e.g., `ifconfig`, `ip link`)

---

### 🔹 Detection Methods

- **MAC address conflicts** on the network
- Frequent CAM table changes for same MAC
- Use of **Network Access Control (NAC)** systems

---

### 🔹 Defense Mechanisms

| Defense                   | Description                                  |
|---------------------------|----------------------------------------------|
| **Port Security**         | Bind specific MAC addresses to switch ports  |
| **Sticky MAC**            | Learn & lock MACs on first connection        |
| **802.1X Authentication** | Authenticate devices before network access   |
| **Monitoring Tools**      | Detect duplicate MACs or flapping entries    |

> MAC spoofing is used for **identity theft** on a LAN. Know how to recognize and stop impersonation attempts via switch security features.
