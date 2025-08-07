# Summarize DDoS Concepts

## What is a DDoS Attack?

A **Distributed Denial of Service (DDoS)** attack is an attempt to make an online service unavailable by overwhelming it with massive traffic from multiple sources (often compromised systems).

---

## How DDoS Attack Works

### Botnets

Botnets are networks of compromised devices (bots) controlled remotely by an attacker (botmaster) to perform malicious activities.

#### Botnets Are Used to Perform:

- **DDoS Attacks** – Overload servers/websites
- **Spamming** – Send bulk unsolicited emails
- **Sniffing Traffic** – Intercept sensitive data
- **Keylogging** – Capture keyboard inputs
- **Spreading Malware** – Infect other machines
- **Installing Adware** – Push ads on victims' browsers
- **Google AdSense Abuse** – Fraudulent ad clicks
- **IRC Network Attacks** – Disrupt chat services
- **Manipulating Polls/Games** – Skew online results
- **Mass Identity Theft** – Steal personal info
- **Credential Stuffing** – Use leaked passwords to breach accounts
- **Cryptocurrency Mining** – Exploit CPU/GPU power

#### A Typical Botnet Setup:

- **Botmaster** controls infected devices via:
  - C2 servers (centralized) or
  - Peer-to-peer channels (decentralized)

#### Botnet Ecosystem:

- Includes:
  - Developers (create malware)
  - Distributors (infect devices)
  - Botnet renters (cybercriminals)
  - Victims (compromised machines)

---

## Scanning Methods for Finding Vulnerable Machines

- **Random Scanning**: Random IPs are probed for vulnerabilities
  - **Hit-list Scanning**: Start with a predefined vulnerable IP list
- **Topological Scanning**: Use data from infected machines to find new targets
- **Local Subnet Scanning**: Target local network addresses first
- **Permutation Scanning**: Shared list shuffled across infected devices to scan efficiently

---

## How Malicious Code Propagates

- **Central Source Propagation**: Malware distributed from a single main server
- **Back-Chaining Propagation**: Follows reverse connections to infect systems (e.g., using IRC/IM)
- **Autonomous Propagation**: Worm-like, spreads without human help once inside the network

---

## DDoS Case Study

### DDoS Attack Scenario

A large botnet floods a target e-commerce site with fake requests, crashing the server and causing hours of downtime, resulting in financial and reputational damage.

---

## Use of Mobile Devices as Botnets

- Attackers exploit mobile OS vulnerabilities or distribute malicious apps
- Mobile botnets launch DDoS attacks, mine cryptocurrency, or spy on users
- More dangerous due to the sheer number and mobility of mobile devices

---

## ✅ Quick Tip for CEH Exam

1. **Understand what DDoS is**: Multiple systems (botnets) flood a target with traffic to make it unavailable.

2. **Botnet roles**:
   - Bots: Infected devices
   - Botmaster: Controls bots
   - Used for: DDoS, keylogging, spamming, mining, etc.

3. **Botnet setup**:
   - Centralized (C2 servers) vs. Decentralized (peer-to-peer)
   - Often rented as a service (Botnet-as-a-Service)

4. **Scanning methods**:
   - Random: Try any IP
   - Hit-list: Use a pre-known list
   - Topological: Use infected host data
   - Subnet: Nearby devices
   - Permutation: Coordinated randomized scan

5. **Propagation types**:
   - Central: One source
   - Back-chaining: Trace backwards from targets
   - Autonomous: Worm-like spread

6. **Mobile device botnets**:
   - Use Android/iOS malware to form mobile botnets
   - Launch DDoS or mine coins without user knowledge

7. **Case study tip**:
   - Real-world example helps explain botnet power and DDoS impact in business downtime or reputation loss.
