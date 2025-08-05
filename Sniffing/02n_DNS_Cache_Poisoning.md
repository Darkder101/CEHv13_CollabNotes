## DNS Cache Poisoning

---

### 🔹 What Is It?

- Attack that **inserts false DNS records** into a DNS server’s or client’s **cache**.
- Users are redirected to **malicious IPs** without knowing—until cache expires (TTL).

---

### 🔹 How It Works

1. Attacker sends a **fake DNS response** to a resolver before the legitimate response arrives.
2. Resolver **caches** the forged response.
3. All future queries for that domain are resolved to the **attacker’s IP**.
4. Can affect:
   - Local host DNS cache
   - ISP or enterprise recursive DNS servers

---

### 🔹 Goal of the Attack

- Redirect users to:
  - Phishing or credential-harvesting sites
  - Malicious download servers
  - Spoofed login pages (e.g., banking or email)

---

### 🔹 Real-World Impact

- **Kaminsky Attack (2008)**: Highlighted severity of cache poisoning flaws in DNS implementations.

---

### 🔹 Tools Used

- `dnsspoof`, `dnschef`, `Ettercap`
- Custom crafted fake DNS responses
- `Scapy` for low-level spoofing

---

### 🔹 Detection Methods

- DNS records resolving to **unexpected IPs**
- Multiple users redirected to the same malicious IP
- Use tools like:
  - `dig`, `nslookup` to compare responses
  - Passive DNS monitoring

---

### 🔹 Defense Mechanisms

| Defense                  | Description                                      |
|--------------------------|--------------------------------------------------|
| **DNSSEC**               | Ensures authenticity of DNS responses            |
| **Randomize source port**| Prevent predictable spoofing                     |
| **Use 0 TTLs**           | Limit cache lifetime of forged entries           |
| **Flush DNS regularly**  | Remove stale or poisoned records                 |

> Cache poisoning attacks are dangerous because they persist silently. Always verify DNS authenticity and enable **DNSSEC**.
