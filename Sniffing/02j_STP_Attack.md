## STP Attack (Spanning Tree Manipulation)

---

### 🔹 What Is It?

- An attacker **exploits STP (Spanning Tree Protocol)** to become the **root bridge**, manipulating the topology to control traffic flow.
- Works at **Layer 2**.

---

### 🔹 How It Works

1. STP elects a **root bridge** based on the **lowest Bridge ID**.
2. Attacker sends **BPDU packets** with a **lower Bridge ID** than the current root.
3. Switches reconfigure → attacker becomes **root bridge**.
4. Traffic now flows through the attacker’s device = **MITM** opportunity.

---

### 🔹 Goal of the Attack

- **Redirect traffic** through attacker's system  
- **Sniff, manipulate, or block** communication  
- **Disrupt network stability**

---

### 🔹 Tools Used

- `Yersinia`
- Custom-crafted **BPDU packets**

---

### 🔹 Detection Methods

- Unexpected **root bridge MAC** in STP topology  
- **Frequent topology changes**  
- Use of monitoring tools (e.g., `Wireshark` BPDU filters)

---

### 🔹 Defense Mechanisms

| Defense                    | Description                                     |
|----------------------------|-------------------------------------------------|
| **Root Guard**             | Prevents ports from becoming root bridge        |
| **BPDU Guard**             | Shuts down ports receiving BPDUs unexpectedly   |
| **PortFast + BPDU Guard**  | Safe for access ports (prevents rogue BPDUs)    |
| **Monitoring STP Changes** | Alerts for topology reconfigurations            |

> STP Attacks target **network topology**, not endpoint data. Always secure STP by enforcing root bridge placement with **Root Guard**.
