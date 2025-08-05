## VLAN Hopping Attack

---

### 🔹 What Is It?

- **VLAN Hopping** is an attack that allows a malicious host in one VLAN to **access traffic or devices in another VLAN**, bypassing segmentation.

---

### 🔹 How It Works

There are **two main methods**:

#### 1. **Switch Spoofing**
- Attacker configures their interface to act like a **trunk port**.
- Switch negotiates → attacker receives **traffic from multiple VLANs**.
- Exploits **Dynamic Trunking Protocol (DTP)** if enabled.

#### 2. **Double Tagging**
- Attacker sends a frame with **two VLAN tags**:
  - Outer tag: VLAN of attacker (legitimate)
  - Inner tag: Target VLAN
- First switch strips outer tag and forwards based on the **inner tag**, reaching the target VLAN.

---

### 🔹 Goals of the Attack

- **Break VLAN isolation**
- Gain access to sensitive or restricted network segments
- **Sniff or attack devices** in other VLANs

---

### 🔹 Tools Used

- Packet crafting tools:
  - `Scapy`
  - `Yersinia`
  - Custom VLAN taggers

---

### 🔹 Detection Methods

- Unexpected inter-VLAN traffic
- Logs showing **DTP negotiations** from user ports
- VLAN tag anomalies in captured packets

---

### 🔹 Defense Mechanisms

| Defense                   | Description                                      |
|---------------------------|--------------------------------------------------|
| **Disable DTP**           | Manually set all ports as access ports           |
| **Set Native VLAN ≠ 1**   | Avoid using VLAN 1 as native for trunk links     |
| **Use VLAN ACLs (VACLs)** | Control traffic between VLANs                    |
| **Limit trunk ports**     | Only enable trunking on trusted interfaces       |

> VLAN Hopping = VLAN bypassing. Know **Switch Spoofing (DTP)** vs **Double Tagging**, and how native VLAN config impacts security.
