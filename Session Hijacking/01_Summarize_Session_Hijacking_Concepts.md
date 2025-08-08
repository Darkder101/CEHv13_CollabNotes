# Summarize Session Hijacking Concepts

Session Hijacking is when an attacker **takes over an existing active session** between a user and a system to impersonate the user, often without them knowing.  
This bypasses authentication because the attacker already has a valid **session token** or **ID**.

---

## 🔹 What is Session Hijacking?

- A **post-authentication attack**.
- Instead of cracking a password, the attacker steals or predicts the **session identifier** that proves the user is logged in.
- Works on **network-level** (TCP/IP sessions) or **application-level** (web sessions).

**Example:**  
If a bank website uses a cookie to store `session_id=abc123`, stealing that cookie lets the attacker act as the user — transfer funds, view data, etc.

---

## 🔹 Why is Session Hijacking Successful?

1. **Weak or Predictable Session IDs**
   - Sequential numbers or timestamp-based values are guessable.
2. **Lack of Encryption**
   - HTTP transmits cookies in plain text; sniffers can capture them.
3. **Session IDs in URL**
   - Can be leaked via logs, referrer headers, or phishing.
4. **Long Session Expiry**
   - Tokens remain valid for hours/days, giving attackers more time.
5. **Token Reuse**
   - Same token before and after login makes interception easier.

---

## 🔹 Session Hijacking Process

1. **Identify Active Session**
   - Recon network traffic or web app tokens.
2. **Steal or Predict Session ID**
   - Using MITM, XSS, brute force, or guessing.
3. **Inject into Attacker's Session**
   - Replace attacker’s cookie/token with victim’s.
4. **Impersonate the User**
   - Perform actions with victim’s privileges.

---

## 🔹 Packet Analysis of a Local Session Hijack

- Capture network traffic (Wireshark, tcpdump).
- Filter for `HTTP` or `Set-Cookie` headers.
- Identify `session_id` values.
- Replay HTTP requests with stolen IDs.

---

## 🔹 Types of Session Hijacking

| Type | Description | Example |
|------|-------------|---------|
| **Passive** | Eavesdropping without interfering with traffic. Used for intelligence gathering. | Sniffing HTTP traffic in a café. |
| **Active** | Actively taking control by injecting packets or commands. | Forcing logout, then logging in as victim. |

---

## 🔹 Session Hijacking in OSI Model

| Layer | Description | Example |
|-------|-------------|---------|
| **Network Level** | Attacks TCP/IP streams directly. | TCP sequence number prediction, ARP spoofing. |
| **Application Level** | Exploits web/app session tokens. | XSS, CSRF, session fixation. |

---

## 🔹 Spoofing vs Hijacking

| Spoofing | Hijacking |
|----------|-----------|
| Pretending to be another identity without seizing their active session. | Taking control of a valid, active session after authentication. |
| Example: Sending emails with a fake sender address. | Example: Stealing someone’s bank session cookie to transfer funds. |

---

## Quick Tip for CEH Exam (with explanations):

- **Exam loves "active vs passive"**: Active = take over, Passive = listen only.
- **Know where it fits in OSI**: Network vs Application.
- **Spoofing ≠ Hijacking**: Spoofing fakes identity; hijacking takes a live session.
- **Weak session IDs** are a big exam red flag in scenarios.
