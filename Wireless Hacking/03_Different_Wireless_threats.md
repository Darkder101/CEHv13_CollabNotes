# Wireless Threats - CEH v13 Study Notes

## Table of Contents
1. [Overview of Wireless Threat Categories](#overview-of-wireless-threat-categories)
2. [Access Control Attacks](#access-control-attacks)
3. [Integrity Attacks](#integrity-attacks)
4. [Confidentiality Attacks](#confidentiality-attacks)
5. [Availability Attacks](#availability-attacks)
6. [Authentication Attacks](#authentication-attacks)
7. [Attack Tools and Techniques](#attack-tools-and-techniques)
8. [Detection and Mitigation Strategies](#detection-and-mitigation-strategies)

## Overview of Wireless Threat Categories

### The CIA Triad in Wireless Security
Wireless threats are categorized based on the fundamental security principles they violate:

- **Confidentiality**: Unauthorized access to sensitive information
- **Integrity**: Unauthorized modification of data or systems
- **Availability**: Prevention of legitimate access to resources
- **Authentication**: Attacks on identity verification mechanisms
- **Access Control**: Bypassing or subverting authorization mechanisms

### Threat Landscape
Wireless networks face unique security challenges due to their broadcast nature, making them susceptible to various attack vectors that don't affect wired networks. Understanding these threats is crucial for implementing appropriate security controls.

## Access Control Attacks

Access control attacks target the mechanisms that determine who can access the wireless network and what resources they can use.

### 1. MAC Spoofing

#### Overview
MAC (Media Access Control) spoofing involves changing the MAC address of a network interface to impersonate another device, bypassing MAC address filtering security measures.

#### Attack Process
1. **Target Identification**: Scan for authorized MAC addresses
2. **MAC Collection**: Use tools like airodump-ng to capture authorized MACs
3. **Interface Configuration**: Change attacker's MAC to match authorized device
4. **Network Access**: Connect using spoofed MAC address
5. **Privilege Escalation**: Exploit trust relationships

#### Technical Implementation
```bash
# Disable interface
ifconfig wlan0 down

# Change MAC address
macchanger -m 00:11:22:33:44:55 wlan0

# Re-enable interface
ifconfig wlan0 up
```

#### Detection Indicators
- Multiple devices with same MAC address
- Unusual traffic patterns from known MAC addresses
- Simultaneous connections from impossible locations
- MAC address changes in DHCP logs

### 2. AP Misconfiguration

#### Common Misconfigurations
- **Default Credentials**: Using factory default usernames/passwords
- **Weak Encryption**: WEP or no encryption enabled
- **Open Administration**: Web interface accessible without authentication
- **Unnecessary Services**: Enabled services like WPS, SNMP, Telnet
- **Poor Placement**: Physical access to reset buttons

#### Exploitation Methods
- **Default Login Attempts**: Try common default credentials
- **Web Interface Access**: Direct access to configuration pages
- **SNMP Enumeration**: Extract configuration via SNMP
- **Firmware Exploitation**: Target known firmware vulnerabilities
- **Physical Access**: Reset to factory defaults

#### Impact
- Complete network compromise
- Configuration changes
- Unauthorized user addition
- Traffic monitoring capabilities
- Backdoor installation

### 3. Ad Hoc Associations

#### Overview
Ad hoc networks allow peer-to-peer connections without infrastructure access points, creating security vulnerabilities when devices automatically connect to nearby ad hoc networks.

#### Attack Scenarios
- **Automatic Connection**: Devices connect to strongest ad hoc signal
- **Data Interception**: Monitor traffic between ad hoc participants  
- **Malware Distribution**: Spread malicious software through file sharing
- **Credential Harvesting**: Capture authentication attempts
- **Lateral Movement**: Use ad hoc connection to access other networks

#### Attack Process
1. **Ad Hoc Network Creation**: Set up malicious ad hoc network
2. **Signal Strength**: Ensure stronger signal than legitimate networks
3. **Auto-Connection**: Wait for victim devices to connect
4. **Traffic Analysis**: Monitor and capture transmitted data
5. **Exploitation**: Launch attacks against connected devices

### 4. Promiscuous Client

#### Definition
Promiscuous clients are devices configured to connect to any available wireless network, often due to misconfiguration or malware infection.

#### Characteristics
- Connects to any open network automatically
- Stores and attempts connection to previously seen SSIDs
- Responds to probe requests indiscriminately
- May have malware-modified network behavior

#### Exploitation
- **Network Mapping**: Gather information about visited networks
- **Credential Extraction**: Harvest stored wireless passwords
- **Traffic Monitoring**: Intercept communications
- **Malware Payload**: Deploy additional malicious software
- **Data Exfiltration**: Steal sensitive information

### 5. Client Mis-association

#### Overview
Client mis-association occurs when legitimate devices connect to unauthorized or malicious access points instead of intended networks.

#### Causes
- **Signal Strength**: Rogue AP with stronger signal
- **SSID Confusion**: Identical or similar network names
- **Automatic Connection**: Devices connecting without user awareness
- **Evil Twin Attacks**: Malicious AP impersonating legitimate network

#### Attack Process
1. **Network Reconnaissance**: Identify legitimate network SSIDs
2. **Rogue AP Setup**: Configure malicious AP with same SSID
3. **Signal Optimization**: Position for stronger signal than legitimate AP
4. **Client Capture**: Wait for devices to connect
5. **Man-in-the-Middle**: Intercept and manipulate traffic

### 6. Unauthorized Association

#### Types of Unauthorized Access
- **Password Cracking**: Breaking WPA/WPA2 passwords
- **WPS Attacks**: Exploiting Wi-Fi Protected Setup vulnerabilities
- **Enterprise Bypass**: Circumventing 802.1X authentication
- **Guest Network Abuse**: Exceeding authorized access privileges
- **Social Engineering**: Obtaining credentials through deception

#### Common Attack Vectors
- **Brute Force**: Systematic password attempts
- **Dictionary Attacks**: Using common password lists
- **Rainbow Tables**: Pre-computed hash lookups
- **Pixie Dust**: WPS PIN recovery attacks
- **Evil Twin**: Credential harvesting through fake APs

## Integrity Attacks

Integrity attacks focus on modifying, injecting, or replaying wireless communications to compromise data authenticity.

### 1. Data Frame Injection

#### Overview
Data frame injection involves crafting and transmitting custom 802.11 frames to manipulate network behavior or inject malicious content.

#### Attack Types
- **Malicious Payload Injection**: Insert harmful content into data streams
- **Protocol Manipulation**: Modify frame headers for specific attacks
- **Traffic Generation**: Create artificial network traffic
- **Response Triggering**: Force specific responses from network devices

#### Technical Process
1. **Frame Crafting**: Create custom 802.11 frames using tools like Scapy
2. **Injection Point**: Identify optimal transmission timing
3. **Frame Transmission**: Inject frames into wireless medium
4. **Response Monitoring**: Observe network reactions
5. **Attack Iteration**: Refine approach based on results

#### Tools and Techniques
```bash
# Using aireplay-ng for frame injection
aireplay-ng -9 -e "TargetSSID" -a 00:11:22:33:44:55 wlan0

# Custom frame injection with Scapy
from scapy.all import *
frame = RadioTap()/Dot11()/Dot11Data()/Raw("Malicious payload")
sendp(frame, iface="wlan0")
```

### 2. WEP Injection

#### WEP-Specific Attacks
- **ARP Request Replay**: Capture and replay ARP packets
- **Chopchop Attack**: Decrypt WEP packets byte by byte
- **Fragmentation Attack**: Use fragment packets for key recovery
- **Interactive Packet Replay**: Modify and replay captured packets

#### Attack Process
1. **Packet Capture**: Monitor WEP-encrypted network traffic
2. **ARP Identification**: Locate ARP request/response pairs
3. **Packet Replay**: Retransmit captured ARP packets
4. **IV Collection**: Gather initialization vectors from responses
5. **Key Recovery**: Use statistical analysis to recover WEP key

### 3. Bit-flipping Injection

#### Concept
Bit-flipping attacks exploit the linear properties of encryption algorithms (particularly RC4 in WEP/TKIP) to modify encrypted data without knowing the encryption key.

#### Attack Mechanics
- **XOR Properties**: Leverage XOR operation characteristics
- **Known Plaintext**: Use predictable data patterns
- **Checksum Weakness**: Exploit linear checksums (CRC-32)
- **Selective Modification**: Change specific bits in encrypted data

#### Implementation
1. **Traffic Capture**: Intercept encrypted frames
2. **Plaintext Prediction**: Identify known data patterns
3. **XOR Calculation**: Calculate required bit changes
4. **Frame Modification**: Flip specific bits in encrypted data
5. **Checksum Adjustment**: Modify CRC to match changes
6. **Frame Retransmission**: Send modified frame

### 4. Extensible AP Injection

#### Description
Attacks targeting extensible authentication protocols through access point manipulation and custom authentication message injection.

#### Attack Vectors
- **EAP Message Spoofing**: Forge EAP authentication messages
- **Certificate Injection**: Insert malicious certificates
- **Authentication Bypass**: Skip authentication steps
- **Protocol Downgrade**: Force weaker authentication methods

### 5. Data Replay

#### Replay Attack Types
- **Session Replay**: Retransmit entire communication sessions
- **Command Replay**: Repeat specific network commands
- **Authentication Replay**: Reuse authentication credentials
- **Packet-Level Replay**: Retransmit individual packets

#### Attack Process
1. **Traffic Capture**: Record legitimate network communications
2. **Timing Analysis**: Determine optimal replay timing
3. **Frame Selection**: Choose packets for maximum impact
4. **Replay Execution**: Retransmit captured frames
5. **Response Analysis**: Monitor network reactions

### 6. Initialization Vector (IV) Replay

#### WEP IV Replay
- **IV Collection**: Gather packets with weak IVs
- **Statistical Analysis**: Identify patterns in IV usage
- **Key Recovery**: Use IV collisions for cryptanalysis
- **Accelerated Cracking**: Speed up WEP key recovery

#### Implementation
```bash
# Capture packets for IV analysis
airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w capture wlan0

# Analyze IVs for weaknesses
aircrack-ng -n 64 capture-01.cap
```

### 7. RADIUS Replay

#### RADIUS Protocol Attacks
- **Message Replay**: Retransmit authentication requests
- **Response Injection**: Forge RADIUS responses
- **Shared Secret Attacks**: Exploit weak RADIUS secrets
- **Accounting Manipulation**: Modify accounting records

#### Attack Scenarios
- **Authentication Bypass**: Replay successful auth responses
- **Session Hijacking**: Take over authenticated sessions  
- **Accounting Fraud**: Manipulate usage records
- **DoS Attacks**: Overwhelm RADIUS servers

### 8. Wireless Network Viruses

#### Propagation Methods
- **Auto-Connection**: Spread through automatic network joining
- **File Sharing**: Propagate via shared network resources
- **Exploit Transmission**: Distribute via network vulnerabilities
- **Configuration Modification**: Alter wireless settings for persistence

#### Characteristics
- **Network-Aware**: Scan for wireless networks automatically
- **Credential Theft**: Steal stored wireless passwords
- **Access Point Infection**: Compromise wireless infrastructure
- **Cross-Platform**: Target multiple operating systems

## Confidentiality Attacks

Confidentiality attacks aim to intercept, decrypt, or gain unauthorized access to sensitive wireless communications.

### 1. Eavesdropping

#### Passive Monitoring
Eavesdropping involves passive interception of wireless communications without alerting the communicating parties.

#### Technical Implementation
- **Monitor Mode**: Configure wireless adapter for passive monitoring
- **Channel Hopping**: Scan across all wireless channels
- **Packet Capture**: Record all transmitted frames
- **Traffic Analysis**: Analyze captured communications

#### Tools and Techniques
```bash
# Enable monitor mode
airmon-ng start wlan0

# Capture all wireless traffic
airodump-ng wlan0mon

# Analyze captured packets
wireshark capture.pcap
```

#### Information Gathered
- **Network Topology**: Identify access points and clients
- **Encryption Status**: Determine security protocols in use
- **Communication Patterns**: Analyze traffic flows
- **Credential Attempts**: Capture authentication exchanges

### 2. Traffic Analysis

#### Methodology
Traffic analysis involves examining communication patterns, timing, and metadata to extract sensitive information even from encrypted communications.

#### Analysis Techniques
- **Pattern Recognition**: Identify recurring communication patterns
- **Timing Correlation**: Analyze communication timing relationships
- **Volume Analysis**: Study data transmission volumes
- **Frequency Mapping**: Monitor communication frequency patterns

#### Attack Process
1. **Long-term Monitoring**: Capture traffic over extended periods
2. **Pattern Identification**: Recognize communication signatures
3. **Correlation Analysis**: Link communications to activities
4. **Information Inference**: Deduce sensitive information from patterns
5. **Intelligence Gathering**: Build comprehensive network profile

### 3. Cracking WEP Keys

#### WEP Vulnerabilities
- **IV Reuse**: 24-bit IV space leads to collisions
- **Weak Key Scheduling**: RC4 key scheduling algorithm flaws
- **Statistical Bias**: Predictable keystream patterns
- **Linear CRC**: Modification detection bypass

#### Attack Methods

#### FMS Attack (Fluhrer, Mantin, Shamir)
- **Weak IV Identification**: Target specific IV patterns
- **Key Byte Recovery**: Recover key bytes sequentially
- **Statistical Analysis**: Use bias in RC4 keystream

#### PTW Attack (Pyshkin, Tews, Weinmann)
- **Improved Statistics**: Enhanced statistical analysis
- **Faster Recovery**: Reduce required packet count
- **Broader IV Coverage**: Use more IV patterns

#### Implementation
```bash
# Capture WEP traffic
airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w wep-crack wlan0mon

# Generate traffic (if needed)
aireplay-ng -3 -b 00:11:22:33:44:55 -h 00:22:33:44:55:66 wlan0mon

# Crack WEP key
aircrack-ng wep-crack-01.cap
```

### 4. Evil Twin AP

#### Overview
Evil Twin attacks involve creating a rogue access point that impersonates a legitimate network to intercept user communications and credentials.

#### Attack Architecture
- **Access Point Spoofing**: Create AP with identical SSID
- **Signal Strength**: Position for stronger signal than legitimate AP
- **Captive Portal**: Present fake authentication pages
- **Traffic Interception**: Monitor all client communications
- **Credential Harvesting**: Capture login credentials

#### Implementation Process
1. **Target Reconnaissance**: Identify legitimate access point details
2. **Deauthentication**: Force clients to disconnect from legitimate AP
3. **Evil Twin Creation**: Set up rogue AP with identical SSID
4. **Client Capture**: Wait for automatic reconnections
5. **Credential Collection**: Present fake login portals
6. **Traffic Monitoring**: Intercept all client communications

#### Technical Setup
```bash
# Create evil twin access point
hostapd evil_twin.conf

# Configure DHCP server
dnsmasq -C dnsmasq.conf

# Set up captive portal
apache2 -D FOREGROUND
```

### 5. Honeypot AP

#### Purpose
Honeypot access points are intentionally vulnerable networks designed to attract and trap attackers for monitoring and analysis purposes.

#### Types
- **Research Honeypots**: Gather attack intelligence
- **Production Honeypots**: Detect attacks on real networks  
- **Decoy Networks**: Divert attention from legitimate systems
- **Forensic Collection**: Gather evidence of attack methods

#### Implementation
- **Weak Security**: Use easily crackable passwords
- **Attractive SSIDs**: Names suggesting valuable content
- **Open Access**: Minimal or no authentication requirements
- **Monitoring Systems**: Comprehensive logging and analysis

### 6. Session Hijacking

#### Overview
Session hijacking involves taking over legitimate user sessions after they've been authenticated to the network.

#### Attack Methods
- **Session Cookie Theft**: Steal authentication tokens
- **Session Fixation**: Force users to use predetermined session IDs
- **Cross-Site Scripting**: Inject scripts to steal session data
- **Man-in-the-Middle**: Intercept and modify session communications

#### Implementation Process
1. **Session Monitoring**: Identify active user sessions
2. **Token Extraction**: Capture session identifiers
3. **Session Replication**: Use stolen tokens for authentication
4. **Access Takeover**: Impersonate legitimate user
5. **Privilege Abuse**: Perform unauthorized actions

### 7. Masquerading

#### Definition
Masquerading involves impersonating legitimate network entities (users, devices, or services) to gain unauthorized access.

#### Impersonation Targets
- **User Identity**: Pose as legitimate network users
- **Device Identity**: Impersonate trusted network devices
- **Service Identity**: Mimic network services or servers
- **Access Point**: Impersonate legitimate infrastructure

#### Attack Techniques
- **Identity Spoofing**: Use stolen or fabricated credentials
- **Certificate Forgery**: Create fake digital certificates
- **Protocol Impersonation**: Mimic legitimate network protocols
- **Service Deception**: Provide fake network services

### 8. Man-in-the-Middle (MITM) Attack

#### Overview
MITM attacks position the attacker between communicating parties to intercept, monitor, and potentially modify their communications.

#### Attack Architecture
- **Interception Point**: Position between client and access point
- **Traffic Forwarding**: Relay communications to maintain connectivity
- **Content Inspection**: Analyze intercepted traffic
- **Selective Modification**: Alter specific communications

#### Implementation Methods
- **Evil Twin**: Rogue access point impersonation
- **ARP Spoofing**: MAC address table manipulation
- **DNS Spoofing**: Redirect domain name resolutions
- **SSL Stripping**: Downgrade HTTPS to HTTP connections

#### Technical Process
1. **Position Establishment**: Insert attacker between parties
2. **Connection Interception**: Capture communication attempts
3. **Proxy Setup**: Establish connections to both parties
4. **Traffic Analysis**: Examine intercepted communications
5. **Selective Injection**: Modify traffic as needed
6. **Transparent Forwarding**: Maintain appearance of normal connectivity

## Availability Attacks

Availability attacks aim to prevent legitimate users from accessing wireless network resources.

### 1. Access Point Theft

#### Physical Security Threats
- **Device Theft**: Physical removal of access points
- **Configuration Access**: Direct physical configuration changes
- **Hardware Tampering**: Installation of malicious hardware
- **Cable Disconnection**: Disruption of network connectivity

#### Impact
- **Service Disruption**: Complete network unavailability
- **Configuration Compromise**: Stolen device configuration data
- **Security Bypass**: Physical access to reset functions
- **Intelligence Gathering**: Analysis of stolen hardware/firmware

#### Mitigation
- **Physical Security**: Secure mounting and enclosures
- **Tamper Detection**: Alerts for physical access attempts
- **Location Monitoring**: GPS tracking for outdoor deployments
- **Quick Recovery**: Rapid replacement procedures

### 2. Denial of Service (DoS)

#### RF Jamming
- **Broadband Jamming**: Transmit noise across entire frequency spectrum
- **Narrowband Jamming**: Target specific channels or frequencies
- **Pulse Jamming**: Intermittent high-power interference
- **Protocol-Aware Jamming**: Target specific protocol elements

#### Implementation
```bash
# Simple deauthentication DoS
aireplay-ng --deauth 0 -a 00:11:22:33:44:55 wlan0mon

# Continuous beacon flood
mdk3 wlan0mon b -f wordlist.txt
```

### 3. Authentication Flood

#### Attack Mechanism
Authentication floods overwhelm access points by sending massive numbers of authentication requests, exhausting system resources.

#### Process
1. **Target Identification**: Identify victim access point
2. **Source Address Variation**: Use multiple source MAC addresses
3. **Request Generation**: Create high volume of auth requests
4. **Resource Exhaustion**: Overwhelm AP processing capacity
5. **Service Denial**: Prevent legitimate authentication attempts

#### Technical Implementation
- **Automated Scripts**: Generate thousands of requests per second
- **MAC Address Randomization**: Avoid source-based filtering
- **Timing Optimization**: Maximize resource consumption
- **Persistence**: Maintain attack duration

### 4. Disassociation Attacks

#### 802.11 Disassociation Frames
Disassociation attacks send forged management frames to forcibly disconnect clients from access points.

#### Attack Process
1. **Client Identification**: Identify connected clients
2. **Frame Crafting**: Create disassociation frames
3. **Source Spoofing**: Impersonate access point MAC address
4. **Frame Transmission**: Send disassociation commands
5. **Reconnection Prevention**: Continuous disassociation

#### Technical Details
```bash
# Disassociate specific client
aireplay-ng --disassoc 10 -a 00:11:22:33:44:55 -c 00:22:33:44:55:66 wlan0mon

# Disassociate all clients
aireplay-ng --disassoc 0 -a 00:11:22:33:44:55 wlan0mon
```

### 5. Deauthentication Flood

#### Overview
Deauthentication attacks are a type of denial-of-service attack that targets communication between users and Wi-Fi access points by sending forged deauthentication frames.

#### Attack Characteristics
- **Management Frame Abuse**: Exploit unprotected 802.11 management frames
- **Spoofed Source**: Impersonate access point or client addresses
- **Broadcast Targeting**: Affect all clients simultaneously
- **Persistent Disruption**: Continuous frame transmission

#### Implementation Variants
- **Client-Targeted**: Deauth specific clients
- **AP-Targeted**: Target access point directly
- **Broadcast**: Affect entire network coverage area
- **Selective**: Target specific device types or users

### 6. ARP Poisoning Attack

#### Layer 2 Attack
ARP poisoning manipulates Address Resolution Protocol tables to redirect network traffic through the attacker's system.

#### Attack Process
1. **Network Reconnaissance**: Identify target clients and gateway
2. **ARP Request Crafting**: Create malicious ARP responses
3. **Table Poisoning**: Corrupt ARP tables on target devices
4. **Traffic Redirection**: Route traffic through attacker system
5. **Continued Poisoning**: Maintain corrupted ARP entries

#### Technical Implementation
```bash
# ARP poisoning with ettercap
ettercap -T -M arp:remote /192.168.1.1/ /192.168.1.100/

# Using arpspoof
arpspoof -i wlan0 -t 192.168.1.100 192.168.1.1
```

### 7. EAP Failure

#### Attack Methods
- **EAP Method Downgrade**: Force weaker authentication methods
- **Certificate Validation Bypass**: Skip certificate verification
- **Credential Capture**: Harvest authentication attempts
- **Authentication Loop**: Trap clients in authentication cycles

#### Implementation
- **Fake RADIUS**: Set up rogue authentication server
- **Certificate Spoofing**: Present invalid certificates
- **Method Negotiation**: Force specific EAP methods
- **Timeout Manipulation**: Cause authentication timeouts

### 8. Routing Attacks

#### Wireless-Specific Routing Issues
- **Route Injection**: Insert malicious routing information
- **Path Manipulation**: Redirect traffic through attacker
- **Routing Table Corruption**: Destroy legitimate routing entries
- **Gateway Impersonation**: Pose as network gateway

#### Attack Scenarios
- **Default Route Hijacking**: Become default gateway for clients
- **Subnet Redirection**: Route specific subnets through attacker
- **Service Discovery Poisoning**: Corrupt service location protocols
- **Dynamic Routing Manipulation**: Exploit routing protocol weaknesses

### 9. Power Saving Attacks

#### 802.11 Power Management
- **Sleep State Manipulation**: Force devices into low-power modes
- **Buffer Overflow**: Overwhelm AP buffering for sleeping clients  
- **Wake Pattern Disruption**: Prevent proper power state transitions
- **Battery Exhaustion**: Force excessive power consumption

#### Attack Implementation
1. **Power State Monitoring**: Identify client power management patterns
2. **Frame Manipulation**: Send power management frames
3. **Buffer Exploitation**: Overwhelm buffering mechanisms
4. **State Confusion**: Create inconsistent power states
5. **Resource Exhaustion**: Drain client and AP resources

### 10. Beacon Flood

#### Beacon Frame Attack
Beacon flooding creates numerous fake access points to overwhelm scanning clients and network monitoring systems.

#### Attack Process
1. **SSID Generation**: Create large numbers of fake SSIDs
2. **Beacon Crafting**: Generate beacon frames with varied parameters
3. **Channel Distribution**: Spread beacons across wireless channels
4. **High-Frequency Transmission**: Send beacons rapidly
5. **Client Confusion**: Overwhelm client scanning capabilities

#### Technical Implementation
```bash
# Generate beacon flood with mdk3
mdk3 wlan0mon b -f ssid_list.txt -a -s 1000

# Custom beacon flood
while true; do
    aireplay-ng -9 -e "FakeAP$RANDOM" wlan0mon
done
```

### 11. TKIP MIC Exploit

#### Michael MIC Countermeasures
TKIP includes countermeasures that shut down the network for 60 seconds when two MIC failures occur within one minute.

#### Attack Process
1. **MIC Failure Generation**: Create frames that fail MIC validation
2. **Timing Control**: Ensure failures occur within countermeasure window
3. **Network Shutdown**: Trigger TKIP countermeasures
4. **Persistent Attack**: Continuously trigger shutdowns
5. **Service Denial**: Prevent network availability

#### Exploitation Details
- **Chopchop Attack**: Use TKIP vulnerabilities to generate MIC failures
- **Packet Modification**: Alter encrypted packets to fail MIC checks
- **Countermeasure Abuse**: Exploit security feature for DoS
- **Timing Precision**: Control failure timing for maximum impact

## Authentication Attacks

Authentication attacks target the mechanisms used to verify user identity and grant network access.

### 1. PSK Cracking

#### WPA/WPA2 Pre-Shared Key Attacks
PSK cracking involves recovering the wireless network password through various cryptographic attacks.

#### Attack Methods

#### Dictionary Attacks
- **Wordlist-Based**: Use common password dictionaries
- **Rule-Based**: Apply transformation rules to base words
- **Hybrid Attacks**: Combine dictionary words with numbers/symbols

#### Brute Force Attacks
- **Comprehensive Search**: Try all possible password combinations
- **Pattern-Based**: Focus on likely password patterns
- **Incremental**: Start with shorter passwords and increase length

#### Rainbow Tables
- **Pre-computed Hashes**: Use pre-calculated password hashes
- **Space-Time Tradeoff**: Exchange storage for computation speed
- **SSID-Specific**: Tables customized for specific network names

#### Technical Implementation
```bash
# Capture WPA handshake
airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w handshake wlan0mon

# Force handshake capture
aireplay-ng --deauth 5 -a 00:11:22:33:44:55 wlan0mon

# Crack with dictionary
aircrack-ng -w wordlist.txt handshake-01.cap

# GPU-accelerated cracking
hashcat -m 2500 handshake.hccapx wordlist.txt
```

### 2. LEAP Cracking

#### LEAP Vulnerabilities
LEAP (Lightweight EAP) uses MS-CHAPv2 authentication, which has known cryptographic weaknesses.

#### Attack Process
1. **LEAP Challenge Capture**: Monitor EAP authentication exchanges
2. **Challenge-Response Analysis**: Extract challenge/response pairs
3. **Dictionary Attack**: Use offline password cracking
4. **Hash Comparison**: Compare computed hashes with captured responses
5. **Password Recovery**: Identify original password

#### Tools and Techniques
```bash
# Capture LEAP authentication
airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w leap wlan0mon

# Extract LEAP challenge/response
asleap -r leap-01.cap -f wordlist.txt

# John the Ripper for LEAP
john --format=mschapv2 leap_hashes.txt
```

### 3. VPN Login Cracking

#### VPN Authentication Attacks
- **Credential Stuffing**: Use leaked username/password combinations
- **Brute Force**: Systematic authentication attempts
- **Dictionary Attacks**: Common password attacks
- **Social Engineering**: Harvest credentials through deception

#### Attack Vectors
- **PPTP Cracking**: Exploit PPTP protocol weaknesses
- **IPSec PSK**: Target pre-shared key authentication
- **SSL VPN**: Attack web-based VPN portals
- **Certificate Attacks**: Target PKI-based authentication

### 4. Domain Login Cracking

#### Windows Domain Authentication
- **Kerberos Attacks**: Target Kerberos authentication protocol
- **NTLM Relay**: Relay domain authentication attempts
- **Password Spraying**: Try common passwords against many accounts
- **Golden Ticket**: Forge Kerberos tickets

#### Attack Methods
- **ASREPRoast**: Target accounts without Kerberos pre-authentication
- **Kerberoasting**: Extract service account hashes
- **DCSync**: Replicate domain controller data
- **Pass-the-Hash**: Use NTLM hashes without passwords

### 5. Key Reinstallation Attack (KRACK)

#### Overview
KRACK (Key Reinstallation Attacks) breaks the WPA2 protocol by forcing nonce reuse in encryption algorithms, discovered by researcher Mathy Vanhoef in 2017.

#### Vulnerability Details
- **4-Way Handshake Flaw**: Exploit message 3 retransmission
- **Nonce Reuse**: Force reuse of cryptographic nonces
- **Key Reinstallation**: Trick client into reinstalling encryption keys
- **Keystream Recovery**: Extract encryption keystream

#### Attack Process
1. **Handshake Interception**: Monitor WPA2 4-way handshake
2. **Message 3 Blocking**: Prevent handshake completion
3. **Retransmission Trigger**: Force AP to retransmit message 3
4. **Key Reinstallation**: Client reinstalls temporal key
5. **Nonce Reset**: Encryption nonce counter resets
6. **Traffic Decryption**: Exploit nonce reuse to decrypt traffic

#### Impact
- **Traffic Decryption**: Decrypt WPA2-protected communications
- **Packet Injection**: Inject malicious data into network
- **Session Hijacking**: Take over user sessions
- **Data Manipulation**: Modify transmitted data

### 6. Identity Theft

#### Wireless Identity Attacks
- **MAC Address Theft**: Impersonate device hardware identities
- **Certificate Stealing**: Extract digital certificates from devices
- **Credential Harvesting**: Capture user authentication credentials
- **Token Theft**: Steal authentication tokens and session identifiers

#### Attack Methods
- **Device Cloning**: Create identical device profiles
- **Certificate Extraction**: Extract private keys from devices
- **Session Token Capture**: Intercept authentication tokens
- **Profile Impersonation**: Use stolen identity information
