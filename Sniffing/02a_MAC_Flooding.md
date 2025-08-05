## MAC Flooding

### 🔹 What Is It?

- **MAC Flooding** is an attack that targets the **CAM table** of a network switch.
- The attacker sends **thousands of fake MAC addresses** to fill up the table.

### 🔹 How It Works

1. Switch stores MAC-to-port mappings in a **CAM table**.
2. Attacker floods the switch with fake MAC addresses.
3. When CAM table is full:
   - Switch can’t learn new addresses.
   - It starts **flooding traffic** to all ports like a hub.
4. Attacker can **sniff packets** not originally destined for them.

---

### 🔹 Goal of the Attack

- **Force the switch** to broadcast traffic.
- Enable **packet sniffing** in a switched network.

---

### 🔹 Tools Used

- `macof` (part of dsniff package)
- `Yersinia`
- Custom packet generators

---

### 🔹 Detection Methods

- Sudden spike in MAC addresses learned
- Unusual broadcast traffic
- Switch logs (if enabled)

---

### 🔹 Defense Mechanisms

| Defense            | Description                             |
|--------------------|-----------------------------------------|
| **Port Security**  | Limit number of MACs per port           |
| **Sticky MAC**     | Bind MAC addresses statically to ports  |
| **Alerts/Logging** | Monitor MAC address learning behavior   |

> Know that MAC flooding exploits switch memory (CAM table), not the protocol itself. Be ready for questions comparing hubs vs. switches in the context of sniffing.

---
