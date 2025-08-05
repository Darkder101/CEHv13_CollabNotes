## Proxy Server DNS Poisoning

---

### 🔹 What Is It?

- In this attack, a **malicious proxy server** is used to **intercept and alter DNS requests** or responses.
- The user’s browser believes DNS was resolved properly, but the proxy **forwards fake IP addresses**.

---

### 🔹 How It Works

1. Victim is tricked into using a **malicious proxy** (via configuration, malware, or rogue DHCP).
2. When the victim accesses a domain, the proxy:
   - **Fakes the DNS resolution**
   - **Redirects** them to malicious sites
3. DNS traffic never reaches a real DNS server.

---

### 🔹 Goal of the Attack

- Stealthily redirect traffic to:
  - Phishing portals
  - Exploit kits
  - MITM proxies for sniffing credentials
- Circumvent traditional DNS security tools

---

### 🔹 Tools Used

- `dnschef`
- `Ettercap` (with DNS spoofing plugin)
- Custom HTTP/HTTPS proxies with DNS manipulation

---

### 🔹 Detection Methods

- Browser using **non-default proxy settings**
- Suspicious entries in:
  - **Proxy server logs**
  - **Browser config / PAC files**
- DNS traffic not appearing on network even though domain access occurs

---

### 🔹 Defense Mechanisms

| Defense                    | Description                                      |
|----------------------------|--------------------------------------------------|
| **Enforce no-proxy policies** | Lock down browser and OS proxy settings        |
| **Use DNS over HTTPS (DoH)** | Encrypt DNS to avoid interception via proxy     |
| **Monitor traffic paths**   | Look for DNS resolution without actual DNS queries |
| **Endpoint protection**     | Detect and block rogue proxy settings           |

> Proxy DNS Poisoning is **browser-level manipulation**. Always check **proxy configs** and enforce strict DNS policies.
