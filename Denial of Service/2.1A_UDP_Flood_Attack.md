# UDP Flood Attack

## Attack Classification
- **Category**: Volumetric Attack
- **OSI Layer**: Layer 4 (Transport)
- **Protocol**: UDP (User Datagram Protocol)

## Attack Mechanism
Floods target with **massive UDP packets** to random or specific ports, consuming network bandwidth and overwhelming the target system.

### How it Works:
1. **Packet Generation**: Send large volumes of UDP packets
2. **Random Ports**: Target random high ports (usually closed)
3. **ICMP Responses**: Target responds with "Port Unreachable" messages
4. **Resource Exhaustion**: Network bandwidth and processing power consumed

## Key Characteristics
- **Connectionless**: UDP doesn't require handshake
- **High Volume**: Measured in Gbps
- **Random Targeting**: Ports 1024-65535 commonly used
- **Amplification Potential**: Can be combined with reflection

## Exam Focus Points

### Identification Symptoms:
- High network utilization
- Massive UDP traffic to random ports
- ICMP "Port Unreachable" responses
- Network congestion and slowdown

### Common Exam Questions:
- **Q**: What type of attack sends UDP packets to random ports?
- **A**: UDP Flood Attack
- **Q**: Why does UDP flood generate ICMP responses?
- **A**: Target sends "Port Unreachable" for closed ports

## Attack Variations
- **UDP Fragment Flood**: Fragmented UDP packets
- **UDP Amplification**: Using DNS, NTP servers
- **Spoofed UDP Flood**: Randomized source IPs

## Detection & Mitigation
- **Rate Limiting**: Limit UDP packets per source
- **Port Filtering**: Block unused UDP ports
- **Traffic Analysis**: Monitor UDP traffic patterns
- **Upstream Filtering**: ISP-level protection

## Common Tools
- **hping3**: `hping3 -2 --flood -p 53 target_ip`
- **Scapy**: Python-based packet crafting
- **LOIC**: Low Orbit Ion Cannon
- **Custom scripts**: Automated UDP flooding
