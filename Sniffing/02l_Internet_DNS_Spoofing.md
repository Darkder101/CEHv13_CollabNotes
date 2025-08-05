## Internet DNS Spoofing

---

### 🔹 What Is It?

- A type of DNS poisoning attack where **DNS records are manipulated outside the victim's local network** (e.g., on public/resolver DNS servers).
- Affects **multiple users across the internet**.

---

### 🔹 How It Works

1. Attacker compromises or exploits a **public DNS resolver** or authoritative DNS server.
2. Malicious DNS entries are **inserted** into the server.
3. Any user querying that domain receives the **fake IP address**.
4. Victims are redirected to **malicious or fake websites**.

---

### 🔹 Goal of the Attack

- Redirect mass traffic to:
  - Phishing sites
  - Botnet command-and-control servers
  - Malware distribution domains
- **Widespread attack vector** affecting many users

---

### 🔹 Real-World Example

- Tampering with DNS records of a **popular domain** like `example.com`
- All users trying to access `example.com` are sent to attacker's IP

---

### 🔹 Tools & Techniques

- `dnscat2`, `dnschef`, or attacker-controlled DNS servers
- May use **BGP hijacking** or **DNS server misconfiguration**

---

### 🔹 Detection Methods

- DNS resolution mismatch across geographic locations
- Public DNS lookup tools (e.g., `dig`, `nslookup`, `DNSViz`)
- Traffic analysis showing users accessing unexpected IPs

---

### 🔹 Defense Mechanisms

| Defense                 | Description                                      |
|-------------------------|--------------------------------------------------|
| **DNSSEC**              | Signs DNS records with cryptographic signatures |
| **Monitoring DNS records** | Use DNS change monitoring tools (e.g., `dnstrails`) |
| **Use Trusted DNS**     | Rely on providers that implement strong security |
| **Zone Transfer Restrictions** | Prevent unauthorized replication of DNS records |

> Internet DNS Spoofing has **wide reach** and is more persistent than local spoofing. DNSSEC is key to verifying trust.
