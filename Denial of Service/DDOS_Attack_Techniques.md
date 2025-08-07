
# Demonstrate Different DDoS Attack Techniques

## Basic Categories of DDoS Attack Vectors

### 1. **Volumetric Attacks**
Attacks that consume bandwidth by overwhelming the network infrastructure with massive traffic.

- **UDP Flood Attack**: Sends large volumes of UDP packets to random ports on a target to overload it.
- **ICMP Flood Attack**: Overwhelms target with ICMP Echo Requests (ping), exhausting resources.
- **Ping of Death Attack**: Sends malformed or oversized ping packets to crash or freeze the system.
- **Smurf Attack**: Sends spoofed ICMP requests to broadcast addresses, amplifying traffic toward the target.
- **Pulse Wave Attack**: Bursts of massive traffic in pulses to bypass auto-scaling and mitigation systems.
- **Zero-Day Attack**: Uses undisclosed vulnerabilities to launch massive-scale traffic overloads.
- **Malformed IP Packet Flood Attack**: Sends broken or incorrect IP headers to confuse or crash systems.
- **Spoofed IP Packet Flood Attack**: Uses fake source IPs to flood systems, making traceback difficult.
- **NTP Amplification Attack**: Spoofs target IP in NTP requests to reflect and amplify traffic at victim.

### 2. **Protocol Attacks**
Target weaknesses in Layer 3/4 protocols (TCP, IP, ICMP).

- **SYN Flood Attack**: Exploits the TCP handshake, sending SYN requests without completing the handshake.
- **Fragmentation Attacks**: Breaks packets into fragments to exhaust the reassembly resources.
- **Spoofed Session Flood Attacks**: Sends fake session packets that consume session tracking tables.
- **ACK Flood Attacks**: Floods servers with ACK packets to overwhelm bandwidth and state tracking.
- **SYN-ACK Flood Attacks**: Targets servers with unsolicited SYN-ACK packets.
- **ACK and PUSH-ACK Flood Attacks**: Overwhelms systems with ACK/PUSH-ACK combinations to exhaust resources.
- **TCP Connection Flood Attacks**: Attempts to create a large number of full TCP connections to overload.
- **TCP State Exhaustion Attacks**: Consumes resources maintaining a large number of half-open or active TCP connections.
- **RST Attacks**: Sends TCP Reset (RST) packets to tear down valid connections.
- **TCP SACK Panic Attacks**: Exploits vulnerabilities in TCP Selective Acknowledgment options.

### 3. **Application Layer Attacks**
Target web servers and applications by exhausting server-side resources.

- **HTTP Flood Attack**: Legitimate HTTP requests (GET/POST) are sent in high volume to crash apps.
- **Slowloris Attack**: Opens many connections and sends partial HTTP requests slowly to tie up threads.
- **UDP Application Layer Flood Attack**: Exploits high-level UDP-based applications (VoIP, DNS) to cause service exhaustion.
- **DDoS Extortion Attack**: Threatens to launch or maintain a DDoS attack unless ransom is paid.

## DDoS Attack Techniques
These techniques are built using the above vectors and combine various tactics:

- **Direct Attacks**: Attackers use their own resources to generate traffic.
- **Reflection Attacks**: Use third-party servers (e.g., NTP, DNS) to reflect traffic to the target.
- **Amplification Attacks**: Small request generates large responses (used in reflection).
- **Multi-Vector Attacks**: Use combinations of volumetric, protocol, and application-layer attacks.
- **IoT Botnets**: Use compromised IoT devices to create massive attack networks.

## DDoS Attack Toolkits

- **ISB (Infrastructure Stress Bot)**: Tool for stress testing and launching various flooding attacks.
- **ultraDDOS-v2**: Known for supporting high-volume and complex DDoS scenarios.
- **Other Toolkits**:
  - LOIC (Low Orbit Ion Cannon)
  - HOIC (High Orbit Ion Cannon)
  - Botnets like Mirai, Mozi, Mantis

---

## 🧠 Quick Tip for CEH Exam

- **Volumetric vs Protocol vs App-layer**: Know which layer each attack targets.
- **NTP/DNS amplification**: Small requests create large responses. Common in real-world attacks.
- **Slowloris vs HTTP Flood**: Slowloris ties up threads slowly; HTTP flood uses legit but massive traffic.
- **SYN flood vs TCP Connection flood**: One is half-open handshake abuse, other completes connections.
- **RST/TCP SACK**: Both target TCP teardown/ack logic.
- **Botnet usage**: DDoS, spam, sniffing, credential stuffing, and crypto mining are core botnet tasks.
- **Multi-vector attack**: Common in modern APTs; know how combinations work.

