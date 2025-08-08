# Explain Application-Level Session Hijacking

Application-level hijacking attacks the **logic of web/app session management** — stealing cookies, predicting tokens, or exploiting browser flaws.

---

## 🔹 a. Session Sniffing

Captures network traffic to find session identifiers.

- Works best on unencrypted HTTP.
- Tools: Wireshark, Bettercap.
- **Real-world**: Attacker on the same Wi-Fi network sniffs cookies.

---

### Compromising Session IDs using Sniffing

- Search captured packets for `Set-Cookie` headers or URL parameters.
- Inject stolen token into attacker’s browser (cookie editor extensions).

---

## 🔹 b. Predictable Session Tokens

If tokens are generated poorly, attackers can **predict** them.

### 1) Analyzing Token Patterns
- **Sequential IDs**: Increment numbers (e.g., 1001, 1002).
- **Timestamp IDs**: Generated from server time; predictable.

### 2) Brute Force Attacks
- **Small Token Space**: Few possibilities = quick guessing.
- **No Rate Limiting**: Unlimited tries without blocking.

### 3) Weak Random Number Generators
- Bad PRNG → attacker can generate same token sequence.

---

## 🔹 c. Man-in-the-Middle (MITM)

- Attacker intercepts traffic between user and server.
- Can inject JavaScript to steal cookies.

---

## 🔹 d. Man-in-the-Browser (MITB)

- Malware inside browser modifies data in real time.
- Bypasses HTTPS since it happens after decryption.

---

## 🔹 e. Cross-Site Scripting (XSS)

- Injects malicious scripts into web pages.
- Script reads cookies (`document.cookie`) and sends to attacker.

---

## 🔹 f. Cross-Site Request Forgery (CSRF)

- Tricks authenticated users into sending malicious requests.
- Example: Auto-submitting a hidden form to transfer funds.

---

## 🔹 g. Session Replay Attack

- Capture → Store → Replay session traffic to impersonate a user.
- Works if server doesn’t expire tokens after first use.

---

## 🔹 h. Session Fixation Attack

- Attacker sets a known session ID before victim logs in.
- Victim authenticates → attacker reuses token.

---

## 🔹 i. CRIME Attack

- Exploits HTTP compression in HTTPS to leak token data.

---

## 🔹 j. Session Hijacking via Proxy Server

- Victim routes through malicious proxy → attacker sees everything.

---

## 🔹 k. Forbidden Attack

- Using stolen token to access restricted pages.

---

## 🔹 l. Session Donation Attack

- Victim intentionally shares session with someone else.
- Often used in insider threats.

---

## Quick Tip for CEH Exam (with explanations):

- **Predictable token** = look for sequential/timestamp IDs.
- **MITM vs MITB**: MITM is network-level; MITB is local to victim’s browser.
- **Session Fixation**: Attacker controls token before login.
- **CRIME**: Related to HTTPS + compression vulnerabilities.
