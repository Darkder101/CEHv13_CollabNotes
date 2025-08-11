## VLAN Hopping Attack
---
### What VLAN Is ?
#### VLAN = Virtual Local Area Network
- It’s like dividing one physical network into multiple separate “virtual” networks.
- Devices in one VLAN can’t directly talk to devices in another VLAN (without a router/firewall in between).
- This improves security and organization.
- Example:
  - VLAN 10 = Staff computers
  - VLAN 20 = Guest Wi-Fi
  - VLAN 30 = Security cameras
- Even though they all connect to the same switch, VLAN rules keep them separate.
---
### What VLAN Hopping is ?

- **VLAN Hopping** is an attack that allows a malicious host in one VLAN to **access traffic or devices in another VLAN**, bypassing segmentation.

---

### How It Works

There are **two main methods**:

#### 1. **Switch Spoofing**
- Normally, the connection between two switches is called a **trunk** — it carries traffic for multiple VLANs.
- Switches use a protocol like **Dynamic Trunking Protocol (DTP)** to agree when a link should be a trunk.
- If an attacker plugs into a port that’s in **dynamic mode** (default in some setups), they can pretend to be a switch.
- The real switch will say, “Sure, let’s be trunk buddies!” and start sending **all VLAN traffic** to the attacker.
- The attacker now sees packets from multiple VLANs, not just their own.

#### 2. **Double Tagging**
- **802.1Q VLAN tagging** works by adding a VLAN ID in the Ethernet frame.
- Normally, a trunk port between switches strips off one VLAN tag before sending traffic to the next hop.
- In double tagging, the attacker sends a frame with **two VLAN tags**:
- **Outer tag** = VLAN attacker is in (e.g., VLAN 10)
- **Inner tag** = Target VLAN (e.g., VLAN 20)
- The first switch sees the **outer tag**, says “This belongs to VLAN 10” (attacker’s VLAN), and strips that tag.
- The frame now has the **inner tag** visible. When it reaches the second switch, that switch sees VLAN 20 and forwards it there.
- Now the attacker’s packet lands in VLAN 20, even though they’re not supposed to be there.

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
