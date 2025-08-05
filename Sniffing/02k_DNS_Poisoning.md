## DNS Poisoning (aka DNS Spoofing)

---

### 🔹 What Is It?

- Attacker **alters DNS responses** to redirect users to **malicious sites** instead of the legitimate ones.
- Exploits the trust in DNS to **manipulate name resolution**.

---

### 🔹 Types of DNS Poisoning

#### 1. **Intranet DNS Spoofing**
- Attacker is **inside the LAN**
- Sends **fake DNS replies** faster than the real DNS server
- Redirects users to phishing or malware sites

#### 2. **Internet DNS Spoofing**
- Manipulation occurs **outside local network**
- Poisoned DNS data **propagates across the Internet**
- Typically involves **compromised DNS servers**

#### 3. **Proxy Server DNS Poisoning**
- Attacker controls a **malicious proxy server**
- DNS resolution is spoofed **through proxy responses**
- Often used in **man-in-the-browser (MitB)** or **phishing campaigns**

#### 4. **DNS Cache Poisoning**
- Attacker corrupts **DNS cache** on recursive resolver or local machine
- Fake records are stored, redirecting multiple users **until TTL expires**

---

### 🔹 Goal of the Attack

- Redirect users to:
  - Phishing pages
  - Malware downloads
  - Fake login portals  
- **Hijack sessions, steal credentials, or inject malicious content**

---

### 🔹 Tools Used

- `dnsspoof` (dsniff suite)
- `Ettercap`
- `Bettercap`
- `dnschef`
- `Metasploit modules`

---

### 🔹 Detection Methods

- Unexpected DNS responses
- DNS logs showing incorrect mappings
- Security tools like `Snort`, `Suricata`, or DNS monitoring systems

---

### 🔹 Defense Mechanisms

| Defense                    | Description                                       |
|----------------------------|---------------------------------------------------|
| **Use DNSSEC**             | Validates DNS responses with digital signatures   |
| **Configure DNS properly** | Disable recursion, restrict external zone transfers |
| **Clear DNS Cache**        | Flush corrupted entries on clients/servers        |
| **Monitor DNS Traffic**    | Watch for anomalies or suspicious IP resolutions  |

> DNS poisoning enables phishing without needing full MITM. **DNSSEC** is the most effective protection.
