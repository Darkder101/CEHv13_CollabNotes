## Tool Focus: Wireshark for Sniffing & Detection

---

### 🔹 Practical Use Cases (Exam & Lab-Focused)

| Objective                     | What to Look for                                   |
|------------------------------|----------------------------------------------------|
| 🔍 **ARP Spoofing**           | Multiple ARP replies with same IP, different MACs  |
| 🧰 **DNS Poisoning**          | DNS responses with mismatched source IPs           |
| 🛑 **DHCP Starvation**        | Flood of DHCP Discover packets from random MACs    |
| ❌ **Rogue DHCP Server**      | DHCP Offers from unauthorized/non-default IPs      |
| 🔓 **Password Sniffing**      | Look at Telnet, FTP, POP3 protocols (clear-text)   |
| 🌐 **Web Traffic Analysis**   | Follow TCP Stream for credentials, session hijack  |
| 📡 **Protocol Identification**| Use “Statistics → Protocol Hierarchy”              |

---

### 🔹 Key Display Filters (Post-Capture Analysis)

| Filter Example                             | Description                                       |
|-------------------------------------------|---------------------------------------------------|
| `ip.addr == 192.168.1.5`                   | Show all packets to/from specific IP             |
| `tcp.port == 80`                           | Filter HTTP packets                              |
| `udp.port == 53`                           | Filter DNS queries and responses                 |
| `arp`                                      | See ARP traffic (for spoofing detection)         |
| `bootp.option.dhcp`                        | Show DHCP packets                                |
| `eth.dst == ff:ff:ff:ff:ff:ff`             | Broadcast traffic                                |
| `dns.qry.name == "example.com"`            | DNS query for a specific domain                  |
| `arp.duplicate-address-detected`           | Built-in ARP spoofing detector                   |
| `frame contains "username"`                | Search for keywords in payload                   |
| `tcp.analysis.retransmission`              | Spot anomalies in TCP sessions                   |

✅ **Exam Tip:** You’ll be tested on filter syntax and spotting traffic anomalies. Memorize a few filters cold.

---

### 🔹 Attack Traces to Recognize

#### 🟡 **ARP Spoofing**
- Multiple ARP replies for the **same IP**
- `Sender MAC` changes frequently
- Display filter: `arp`

#### 🔴 **DHCP Starvation**
- Flood of:
  - `DHCP Discover` from many random MACs
- No IPs left to assign by DHCP server
- Filter: `bootp`

#### 🟣 **Rogue DHCP Server**
- Two or more **DHCP Offers**
- One from legitimate server (e.g., `.1`)
- One from rogue IP (e.g., `.254`)

#### 🔵 **DNS Poisoning**
- Multiple **DNS replies** for a query
- Suspicious IP in response
- Filter: `dns` + check for wrong `src` IP

---

### 🔹 Tools & Features to Use in Wireshark

| Feature                    | What It Helps With                               |
|----------------------------|---------------------------------------------------|
| **Follow TCP Stream**      | Reconstruct login pages / sessions                |
| **Color Rules**            | Highlight protocols (TCP = blue, ARP = yellow)   |
| **Statistics → Protocols** | Analyze traffic mix (HTTP, FTP, etc.)            |
| **Expert Info**            | Flags retransmits, malformed packets, warnings   |
| **I/O Graphs**             | Plot traffic spikes (e.g., DHCP floods)          |
| **Export Objects → HTTP**  | Download files seen in HTTP traffic              |

---

### 🔹 Quick Tips for CEH Labs & Exams

- Use **filters** instead of scrolling through thousands of packets.
- Always check for **ARP**, **DNS**, and **DHCP** patterns in spoofing scenarios.
- Know how to identify **promiscuous mode** captures.
- Be comfortable using both GUI and keyboard shortcuts.
