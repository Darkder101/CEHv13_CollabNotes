# Sniffing Techniques

## 📌 Objective

This section introduces **common sniffing techniques** and attack methods used to intercept, manipulate, or redirect network traffic in **switched environments**.

---

## 🔹 Why Sniffing Techniques Are Needed

- In **hub-based networks**, sniffing is easy (broadcast traffic).
- In **switched networks**, traffic is segmented — attackers must use **special techniques** to:
  - Force switches to behave like hubs
  - Redirect or mirror traffic
  - Exploit protocol weaknesses

---

## 🔹 Common Sniffing Techniques

| Technique                | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| **MAC Flooding**         | Fills switch CAM table with fake MACs → causes broadcast behavior          |
| **Switch Port Stealing** | Hijacks a switch port by spoofing a legitimate MAC                         |
| **DHCP Starvation**      | Exhausts DHCP IP pool using fake requests                                  |
| **Rogue DHCP Server**    | Sends malicious IP/gateway via fake DHCP replies                           |
| **ARP Spoofing**         | Sends forged ARP replies to intercept traffic (MITM)                       |
| **MAC Spoofing**         | Changes MAC to impersonate another device                                  |
| **IRDP Spoofing**        | Fakes router discovery messages                                             |
| **VLAN Hopping**         | Escapes VLAN boundaries to access other VLANs                              |
| **STP Attack**           | Becomes root bridge to control switch path                                 |
| **DNS Poisoning**        | Redirects users to fake/malicious domains                                  |
| **DNS Cache Poisoning**  | Corrupts DNS resolver cache with false entries                             |

---

## 🔹 Exam Focus Points

- Know which techniques **bypass switch isolation**
- Understand the **goal** of each technique:
  - Packet capture
  - Redirection
  - Network manipulation
- Be able to identify **defensive measures** (e.g., DHCP snooping, DAI, port security)
