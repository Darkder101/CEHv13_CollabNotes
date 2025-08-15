# Wireless Encryption Algorithms - CEH v13 Study Notes

## Table of Contents
1. [Overview of Wireless Security](#overview-of-wireless-security)
2. [WEP (Wired Equivalent Privacy)](#wep-wired-equivalent-privacy)
3. [EAP (Extensible Authentication Protocol)](#eap-extensible-authentication-protocol)
4. [LEAP (Lightweight EAP)](#leap-lightweight-eap)
5. [WPA (Wi-Fi Protected Access)](#wpa-wi-fi-protected-access)
6. [TKIP (Temporal Key Integrity Protocol)](#tkip-temporal-key-integrity-protocol)
7. [WPA2 (Wi-Fi Protected Access 2)](#wpa2-wi-fi-protected-access-2)
8. [AES (Advanced Encryption Standard)](#aes-advanced-encryption-standard)
9. [CCMP (Counter Mode Cipher Block Chaining Message Authentication Code Protocol)](#ccmp-counter-mode-cipher-block-chaining-message-authentication-code-protocol)
10. [WPA2 Enterprise](#wpa2-enterprise)
11. [RADIUS (Remote Authentication Dial-In User Service)](#radius-remote-authentication-dial-in-user-service)
12. [PEAP (Protected Extensible Authentication Protocol)](#peap-protected-extensible-authentication-protocol)
13. [WPA3 (Wi-Fi Protected Access 3)](#wpa3-wi-fi-protected-access-3)
14. [Security Comparison Matrix](#security-comparison-matrix)
15. [Attack Vectors and Vulnerabilities](#attack-vectors-and-vulnerabilities)

## Overview of Wireless Security

### Evolution of Wireless Security
Wireless security has evolved through several generations to address increasing security threats:

1. **WEP (1997)**: First wireless security standard - fundamentally flawed
2. **WPA (2003)**: Interim solution to address WEP vulnerabilities
3. **WPA2 (2004)**: Robust security with AES encryption
4. **WPA3 (2018)**: Latest standard with enhanced security features

### Key Security Components
- **Authentication**: Verifying user identity
- **Authorization**: Granting access permissions
- **Encryption**: Protecting data confidentiality
- **Integrity**: Ensuring data hasn't been modified
- **Key Management**: Secure generation and distribution of encryption keys

## WEP (Wired Equivalent Privacy)

### Overview
WEP was the original security protocol for wireless networks, developed in 1997 as part of the IEEE 802.11 standard. It aimed to provide security equivalent to wired networks but had fundamental design flaws.

### Technical Specifications
- **Encryption Algorithm**: RC4 stream cipher
- **Key Lengths**: 64-bit (40-bit effective) and 128-bit (104-bit effective)
- **Authentication**: Open System or Shared Key
- **Initialization Vector (IV)**: 24-bit (major weakness)

### Operational Flow
<img width="1207" height="426" alt="image" src="https://github.com/user-attachments/assets/ba7dae19-0720-4b3a-a46a-3a5a0f2a426a" />

#### WEP Encryption Process:
1. **Plaintext Preparation**: Original data is prepared for encryption
2. **IV Generation**: 24-bit Initialization Vector is generated (or incremented)
3. **Key Combination**: IV is concatenated with the shared WEP key
4. **RC4 Keystream**: Combined key generates RC4 keystream
5. **XOR Operation**: Plaintext XOR keystream = ciphertext
6. **ICV Calculation**: Integrity Check Value (CRC-32) is calculated
7. **Frame Assembly**: IV + Encrypted(Data + ICV) forms the frame
8. **Transmission**: Encrypted frame is transmitted

#### WEP Decryption Process:
1. **Frame Reception**: Encrypted frame received
2. **IV Extraction**: 24-bit IV extracted from frame header
3. **Key Reconstruction**: IV + shared key recreates encryption key
4. **RC4 Keystream**: Same keystream generated as encryption
5. **XOR Decryption**: Ciphertext XOR keystream = plaintext + ICV
6. **Integrity Check**: CRC-32 verification of decrypted data
7. **Data Delivery**: Verified plaintext delivered to upper layers

### WEP Vulnerabilities
- **Weak IV**: 24-bit IV creates keystream reuse after ~5000 packets
- **Static Keys**: Same key used across all devices and sessions
- **No Key Management**: Manual key distribution and updates
- **CRC-32 Weakness**: Linear checksum vulnerable to bit-flipping attacks
- **Authentication Flaws**: Shared key authentication reveals keystream

### WEP Attack Methods
- **IV Collection**: Capture packets to find IV collisions
- **Statistical Analysis**: Analyze patterns in encrypted traffic
- **Keystream Recovery**: Extract keystream from known plaintext
- **Bit-flipping Attacks**: Modify encrypted data without detection
- **Authentication Bypass**: Exploit shared key authentication

## EAP (Extensible Authentication Protocol)

### Overview
EAP is a framework for authentication that supports multiple authentication methods and is well-supported among wireless vendors. It provides a flexible structure for implementing various authentication mechanisms.

### EAP Framework Components
- **EAP Peer**: Client device requesting network access
- **EAP Authenticator**: Network access device (Access Point/Switch)
- **EAP Authentication Server**: RADIUS server performing authentication

### Operational Flow

#### EAP Authentication Process:
1. **Association**: Client associates with Access Point
2. **EAP Start**: Authenticator sends EAP-Request/Identity
3. **Identity Response**: Client responds with username/identity
4. **Method Negotiation**: Server selects appropriate EAP method
5. **Challenge-Response**: Multiple rounds of authentication challenges
6. **Authentication Decision**: Server makes accept/reject decision
7. **Key Derivation**: Successful authentication generates encryption keys
8. **Access Grant**: Network access granted with appropriate keys

### EAP Methods
- **EAP-MD5**: Simple challenge-response (insecure for wireless)
- **EAP-TLS**: Certificate-based authentication
- **EAP-TTLS**: Tunneled TLS with legacy authentication
- **EAP-PEAP**: Protected EAP with TLS tunnel
- **EAP-FAST**: Flexible Authentication via Secure Tunneling

### EAP Security Features
- **Mutual Authentication**: Both client and server authenticate
- **Key Derivation**: Generates unique session keys
- **Method Flexibility**: Supports various authentication types
- **Replay Protection**: Prevents replay attacks

## LEAP (Lightweight EAP)

### Overview
LEAP is a Cisco proprietary protocol that was vulnerable to dictionary attacks, though Cisco maintained it could be secure with sufficiently complex passwords.

### Technical Specifications
- **Developer**: Cisco Systems (proprietary)
- **Authentication Method**: MS-CHAPv2 based
- **Key Management**: Dynamic WEP key generation
- **Mutual Authentication**: Yes (client and server)

### Operational Flow

#### LEAP Authentication Process:
1. **EAP-Request/Identity**: Access Point requests client identity
2. **Identity Response**: Client provides username
3. **LEAP Challenge**: Server sends random challenge to client
4. **Client Response**: Client computes response using password hash
5. **Server Validation**: Server validates client response
6. **Server Challenge**: Server sends challenge to client for mutual auth
7. **Client Validation**: Client validates server using shared password
8. **Key Generation**: Dynamic WEP keys generated from authentication
9. **Re-authentication**: Periodic re-authentication with new keys

### LEAP Vulnerabilities
- **Dictionary Attacks**: Weak password hashing vulnerable to offline attacks
- **Password Cracking**: Tools like ASLEAP can crack LEAP passwords
- **MS-CHAPv2 Weakness**: Underlying protocol has known vulnerabilities
- **No Certificate Validation**: Susceptible to man-in-the-middle attacks

### LEAP Security Recommendations
- **Complex Passwords**: Minimum 8 characters with mixed case/symbols
- **Regular Password Changes**: Frequent password rotation
- **Migration Path**: Upgrade to EAP-FAST, PEAP, or EAP-TLS
- **Network Monitoring**: Monitor for attack attempts

## WPA (Wi-Fi Protected Access)

### Overview
WPA became available in 2003 as an intermediate measure in anticipation of the more secure WPA2. It was designed to address WEP's critical vulnerabilities while maintaining backward compatibility.

### Technical Specifications
- **Encryption**: TKIP (Temporal Key Integrity Protocol)
- **Authentication**: Pre-Shared Key (PSK) or 802.1X/EAP
- **Key Management**: Dynamic key generation and rotation
- **Integrity**: Michael Message Integrity Check (MIC)

### Operational Flow
<img width="1180" height="393" alt="image" src="https://github.com/user-attachments/assets/f0319eb7-2635-4b52-a236-11cc23c19db0" />

#### WPA Authentication Process (PSK):
1. **Association**: Client associates with Access Point
2. **4-Way Handshake Initiation**: AP sends ANonce (random number)
3. **PTK Generation**: Client generates Pairwise Transient Key
4. **SNonce Response**: Client sends SNonce + MIC to AP
5. **Key Confirmation**: AP validates MIC and sends GTK (Group Temporal Key)
6. **Handshake Completion**: Client acknowledges GTK installation
7. **Data Encryption**: Secure communication using derived keys

#### WPA Key Hierarchy:
1. **PMK (Pairwise Master Key)**: Derived from PSK or EAP authentication
2. **PTK (Pairwise Transient Key)**: Session-specific encryption key
3. **GTK (Group Temporal Key)**: Multicast/broadcast encryption key
4. **Temporal Keys**: Used for actual data encryption

### WPA Security Improvements over WEP
- **Dynamic Keys**: Per-session key generation
- **Stronger Integrity**: Michael MIC instead of CRC-32
- **Key Rotation**: Automatic key updates
- **Message Replay Protection**: Sequence number validation

### WPA Vulnerabilities
- **TKIP Weaknesses**: Susceptible to certain cryptographic attacks
- **Michael MIC Limitations**: Weaker than CCMP integrity protection
- **PSK Dictionary Attacks**: Weak passphrases vulnerable to offline attacks

## TKIP (Temporal Key Integrity Protocol)

### Overview
TKIP was developed as a software-upgradeable solution to replace WEP's static encryption while maintaining compatibility with existing hardware.

### Technical Specifications
- **Base Cipher**: RC4 (same as WEP)
- **Key Size**: 128-bit temporal keys
- **Key Mixing**: Per-packet key mixing function
- **Integrity**: Michael Message Integrity Check
- **Replay Protection**: 48-bit sequence number

### Operational Flow

#### TKIP Encryption Process:
1. **Temporal Key Selection**: Select appropriate temporal key (TK)
2. **Phase 1 Key Mixing**: Mix TK with Transmitter Address and high bits of TSC
3. **Phase 2 Key Mixing**: Mix Phase 1 output with low bits of TSC
4. **IV Construction**: Create 48-bit IV from TSC
5. **RC4 Key Generation**: Combine mixed key with IV
6. **Data Encryption**: Encrypt plaintext + Michael MIC
7. **Frame Assembly**: TSC + Encrypted data transmitted

#### TKIP Key Management:
1. **Temporal Key (TK)**: 128-bit encryption key
2. **Transmit Sequence Counter (TSC)**: 48-bit replay protection
3. **Michael MIC Key**: 64-bit integrity key
4. **Key Mixing Function**: Prevents weak key attacks

### TKIP Security Features
- **Per-Packet Keys**: Unique encryption key for each packet
- **MIC Protection**: 64-bit Message Integrity Check
- **Key Rotation**: Automatic key updates
- **Hardware Compatibility**: Works with WEP-capable hardware

### TKIP Vulnerabilities
- **Chopchop Attacks**: Recover keystream through packet manipulation
- **Beck-Tews Attack**: Exploit key mixing algorithm weaknesses
- **RC4 Weaknesses**: Inherits RC4 statistical biases

## WPA2 (Wi-Fi Protected Access 2)

### Overview
WPA2 became available in 2004 and provides robust security with AES encryption. It became the gold standard for wireless security until WPA3's introduction.

### Technical Specifications
- **Encryption**: AES-CCMP (Counter Mode Cipher Block Chaining MAC Protocol)
- **Authentication**: PSK or 802.1X/EAP
- **Key Size**: 128-bit AES keys
- **Integrity**: CCMP provides both confidentiality and integrity

### Operational Flow
<img width="947" height="668" alt="image" src="https://github.com/user-attachments/assets/a2df7185-6d13-47e7-9ff5-99da561b44d2" />

#### WPA2 Authentication Process (PSK):
1. **Initial Association**: Client associates with Access Point
2. **PMK Derivation**: PSK becomes Pairwise Master Key
3. **4-Way Handshake**:
   - **Message 1**: AP → Client (ANonce)
   - **Message 2**: Client → AP (SNonce + MIC)
   - **Message 3**: AP → Client (GTK + MIC)
   - **Message 4**: Client → AP (ACK)
4. **Key Installation**: Both parties install encryption keys
5. **Secure Communication**: AES-CCMP encryption active

#### WPA2 Key Derivation:
1. **PSK**: Pre-Shared Key (from passphrase)
2. **PMK**: Pairwise Master Key (PSK or EAP-derived)
3. **PTK**: Pairwise Transient Key (session-specific)
4. **GTK**: Group Temporal Key (multicast/broadcast)

### WPA2 Security Advantages
- **AES Encryption**: Military-grade symmetric encryption
- **CCMP Integrity**: Strong authentication and integrity protection
- **Perfect Forward Secrecy**: Session keys independent of long-term keys
- **Robust Key Management**: Secure key derivation and distribution

### WPA2 Vulnerabilities
- **PSK Dictionary Attacks**: Weak passphrases vulnerable to brute force
- **KRACK Attack**: Key reinstallation attacks against 4-way handshake
- **Downgrade Attacks**: Force clients to use weaker security protocols

## AES (Advanced Encryption Standard)

### Overview
AES is a symmetric block cipher that became the U.S. federal government standard and is widely adopted in WPA2 and WPA3 implementations.

### Technical Specifications
- **Block Size**: 128-bit fixed block size
- **Key Sizes**: 128-bit, 192-bit, or 256-bit keys
- **Algorithm**: Substitution-permutation network
- **Rounds**: 10 (128-bit), 12 (192-bit), 14 (256-bit) rounds

### Operational Flow

#### AES Encryption Process:
1. **Key Expansion**: Original key expanded into round keys
2. **Initial Round**: AddRoundKey operation
3. **Main Rounds** (9, 11, or 13 rounds):
   - **SubBytes**: Byte substitution using S-box
   - **ShiftRows**: Cyclical shift of row bytes
   - **MixColumns**: Column mixing transformation
   - **AddRoundKey**: XOR with round key
4. **Final Round**: SubBytes, ShiftRows, AddRoundKey (no MixColumns)
5. **Ciphertext Output**: 128-bit encrypted block

#### AES in Wireless Context:
- **Counter Mode**: AES-CTR for confidentiality
- **CBC-MAC**: AES-CBC for integrity
- **CCMP**: Combines CTR mode encryption with CBC-MAC authentication

### AES Security Properties
- **Proven Security**: Extensive cryptanalysis over 20+ years
- **Fast Implementation**: Efficient in both hardware and software
- **No Known Practical Attacks**: Resistant to known cryptographic attacks
- **Government Standard**: NIST-approved encryption algorithm

## CCMP (Counter Mode Cipher Block Chaining Message Authentication Code Protocol)

### Overview
CCMP is the encryption protocol used in WPA2 that combines AES Counter mode for confidentiality with CBC-MAC for authentication and integrity.

### Technical Specifications
- **Encryption**: AES-CTR (Counter mode)
- **Authentication**: AES-CBC-MAC
- **Key Size**: 128-bit AES keys
- **Nonce**: 48-bit packet number for CTR mode
- **MIC**: 64-bit Message Integrity Check

### Operational Flow

#### CCMP Encryption Process:
1. **Nonce Construction**: Combine packet number, address, and priority
2. **Additional Authentication Data (AAD)**: Construct from MAC header
3. **Counter Mode Encryption**:
   - Generate counter blocks from nonce
   - Encrypt counters with AES
   - XOR plaintext with keystream
4. **CBC-MAC Calculation**:
   - Format AAD and plaintext into blocks
   - Compute CBC-MAC using AES
5. **MIC Truncation**: Truncate CBC-MAC to 64 bits
6. **Frame Assembly**: Encrypted data + MIC

#### CCMP Decryption Process:
1. **Frame Parsing**: Extract encrypted data and MIC
2. **Counter Regeneration**: Reconstruct counter blocks
3. **Decryption**: XOR ciphertext with regenerated keystream
4. **Authentication**: Recompute CBC-MAC over AAD and plaintext
5. **Verification**: Compare computed MIC with received MIC
6. **Data Delivery**: Deliver plaintext if MIC matches

### CCMP Security Features
- **Authenticated Encryption**: Provides both confidentiality and integrity
- **Replay Protection**: Packet number prevents replay attacks
- **Key Separation**: Separate keys for encryption and authentication
- **Perfect Forward Secrecy**: Temporal keys don't compromise long-term keys

## WPA2 Enterprise

### Overview
WPA2 Enterprise uses 802.1X authentication with EAP methods and RADIUS servers to provide centralized authentication and authorization for large organizations.

### Architecture Components
- **Supplicant**: Client device with 802.1X capability
- **Authenticator**: Access Point or Wireless Controller
- **Authentication Server**: RADIUS server with user database

### Operational Flow

#### WPA2 Enterprise Authentication:
1. **Association**: Client associates with Access Point
2. **EAP Start**: AP sends EAP-Request/Identity
3. **Identity Response**: Client provides username
4. **RADIUS Access-Request**: AP forwards credentials to RADIUS server
5. **EAP Method Selection**: Server chooses appropriate EAP method
6. **Authentication Exchange**: Multiple EAP request/response cycles
7. **RADIUS Access-Accept**: Server sends accept with encryption keys
8. **Key Distribution**: RADIUS-derived keys distributed to AP
9. **4-Way Handshake**: Standard WPA2 handshake with EAP-derived PMK
10. **Secure Access**: Client granted network access

### Enterprise EAP Methods
- **EAP-TLS**: Certificate-based mutual authentication
- **EAP-TTLS**: Username/password inside TLS tunnel
- **PEAP**: Microsoft's protected EAP implementation
- **EAP-FAST**: Cisco's fast authentication method

### WPA2 Enterprise Benefits
- **Centralized Authentication**: Single user database for entire network
- **Per-User Keys**: Unique encryption keys for each user session
- **Certificate Management**: PKI integration for strong authentication
- **Accounting**: Detailed logs of user authentication and access
- **Policy Enforcement**: Role-based access control

## RADIUS (Remote Authentication Dial-In User Service)

### Overview
RADIUS is a network protocol that provides centralized authentication, authorization, and accounting for network access. It's commonly used in enterprise wireless deployments.

### RADIUS Components
- **RADIUS Client**: Network Access Server (NAS) - Access Point/Controller
- **RADIUS Server**: Authentication server with user database
- **RADIUS Proxy**: Forwards requests between multiple RADIUS servers

### Operational Flow

#### RADIUS Authentication Process:
1. **Access-Request**: NAS sends authentication request to RADIUS server
2. **User Lookup**: Server queries user database for credentials
3. **Challenge Processing**: Server may send Access-Challenge for additional info
4. **Authentication Validation**: Server validates user credentials
5. **Access-Accept/Reject**: Server responds with accept or reject
6. **Attribute Delivery**: Accept includes user attributes and encryption keys
7. **Accounting Start**: NAS sends accounting start record
8. **Session Monitoring**: Periodic accounting updates
9. **Accounting Stop**: Session termination record sent

### RADIUS Attributes
- **User-Name**: Account username
- **User-Password**: Encrypted password
- **NAS-IP-Address**: IP address of network access server
- **Session-Timeout**: Maximum session duration
- **Filter-Id**: Access control list identifier
- **Vendor-Specific**: Proprietary attributes

### RADIUS Security Features
- **Shared Secret**: Pre-shared key between client and server
- **Message Authentication**: MD5 hash prevents tampering
- **Password Encryption**: User-Password attribute encrypted
- **Accounting Records**: Detailed session information

### RADIUS Limitations
- **UDP Protocol**: No guaranteed delivery
- **Shared Secret Security**: Pre-shared keys can be compromised
- **Password Encryption**: Only User-Password encrypted by default
- **No Perfect Forward Secrecy**: Compromise of shared secret affects all sessions

## PEAP (Protected Extensible Authentication Protocol)

### Overview
PEAP provides a TLS tunnel to protect the authentication process and is widely supported across different platforms.

### PEAP Components
- **Outer Authentication**: TLS tunnel establishment
- **Inner Authentication**: EAP method within TLS tunnel
- **Certificate Validation**: Server certificate verification
- **Credential Protection**: Username/password encrypted

### Operational Flow

#### PEAP Authentication Process:
1. **EAP-Identity**: Client identity requested
2. **PEAP Start**: Server initiates PEAP negotiation
3. **TLS Handshake**:
   - Server sends certificate
   - Client validates certificate
   - TLS tunnel established
4. **Inner EAP Method**: Protected authentication within tunnel
5. **Credential Exchange**: Username/password sent securely
6. **Authentication Result**: Server validates inner credentials
7. **Key Derivation**: TLS master secret derives encryption keys
8. **Tunnel Termination**: TLS tunnel closed after key exchange

### PEAP Versions
- **PEAPv0/MS-CHAPv2**: Microsoft implementation with challenge-response
- **PEAPv1/GTC**: Generic Token Card authentication
- **PEAPv0/TLS**: Certificate authentication within PEAP tunnel

### PEAP Security Features
- **Mutual Authentication**: Optional client certificate validation
- **Credential Protection**: Inner credentials encrypted in TLS tunnel
- **Server Validation**: Certificate-based server authentication
- **Replay Protection**: TLS sequence numbers prevent replay

### PEAP Vulnerabilities
- **Certificate Validation**: Users often ignore certificate warnings
- **Inner Method Weaknesses**: MS-CHAPv2 has known vulnerabilities
- **Man-in-the-Middle**: Improper certificate validation enables attacks

## WPA3 (Wi-Fi Protected Access 3)

### Overview
WPA3 offers several advantages over WPA2 in terms of security and features. It addresses known vulnerabilities in WPA2 and provides enhanced security for modern wireless networks.

### WPA3 Improvements
- **SAE (Simultaneous Authentication of Equals)**: Replaces PSK with stronger authentication
- **Perfect Forward Secrecy**: Session keys don't compromise long-term keys
- **Brute Force Protection**: Limits offline dictionary attacks
- **Enhanced Open**: Opportunistic Wireless Encryption for open networks

### Technical Specifications
- **Personal**: SAE authentication with 128-bit encryption
- **Enterprise**: 192-bit security mode available
- **Encryption**: AES-256 in enterprise mode
- **Key Derivation**: Improved key generation algorithms

### Operational Flow

#### WPA3-SAE Authentication Process:
1. **SAE Commit**: Both parties send commit messages with scalars/elements
2. **SAE Confirm**: Exchange confirm messages with proof of key knowledge
3. **PMK Derivation**: Password Element (PE) and shared secret generate PMK
4. **4-Way Handshake**: Standard handshake with SAE-derived PMK
5. **Enhanced Security**: Perfect forward secrecy and brute force protection

#### WPA3 Enhanced Open:
1. **Association**: Client associates with open network
2. **OWE (Opportunistic Wireless Encryption)**: Diffie-Hellman key exchange
3. **Shared Secret**: Both parties derive encryption keys
4. **Data Protection**: Encrypted communication without pre-shared password

### WPA3 Security Enhancements
- **Dictionary Attack Resistance**: SAE prevents offline password attacks
- **Forward Secrecy**: Compromise of long-term key doesn't affect past sessions
- **Stronger Encryption**: 256-bit encryption available in enterprise mode
- **Protection in Open Networks**: Encryption even without passwords

### WPA3 Deployment Challenges
- **Hardware Requirements**: New devices needed for full WPA3 support
- **Compatibility**: Mixed WPA2/WPA3 environments during transition
- **Configuration Complexity**: Enterprise mode requires careful setup

## Security Comparison Matrix

| Protocol | Year | Encryption | Key Length | Authentication | Vulnerabilities | Status |
|----------|------|------------|------------|----------------|-----------------|---------|
| **WEP** | 1997 | RC4 | 64/128-bit | Open/Shared Key | IV reuse, weak keys | Deprecated |
| **WPA** | 2003 | TKIP/RC4 | 128-bit | PSK/802.1X | TKIP attacks | Legacy |
| **WPA2** | 2004 | AES-CCMP | 128-bit | PSK/802.1X | PSK brute force, KRACK | Current |
| **WPA3** | 2018 | AES-CCMP/GCMP | 128/256-bit | SAE/802.1X | Implementation bugs | Latest |

### Protocol Security Levels
1. **WEP**: ❌ Insecure - Should not be used
2. **WPA**: ⚠️ Legacy - Upgrade recommended
3. **WPA2**: ✅ Secure - Current standard
4. **WPA3**: ✅ Most Secure - Future-proof

---

## Key CEH v13 Exam Points

### Critical Concepts
1. **Protocol Evolution**: Understand progression from WEP → WPA → WPA2 → WPA3
2. **Key Management**: Master the 4-way handshake process
3. **Authentication Methods**: Differentiate PSK vs Enterprise authentication
4. **Vulnerabilities**: Know specific attacks for each protocol
5. **EAP Methods**: Understand different EAP types and their security
6. **Attack Tools**: Familiarize with Aircrack-ng, Hashcat, and Wireshark
7. **Defense Techniques**: Security hardening and monitoring practices

### Exam Focus Areas
- **WEP Weaknesses**: IV reuse, weak key generation, CRC-32 flaws
- **WPA2 KRACK**: Key reinstallation attack mechanisms
- **EAP Security**: Compare EAP-TLS, PEAP, and LEAP security levels
- **RADIUS Protocol**: Authentication, Authorization, Accounting process
- **WPA3 Features**: SAE authentication and enhanced security
- **Attack Methodologies**: Passive monitoring vs active attacks
- **Enterprise Security**: 802.1X deployment and certificate management

### Practical Skills
- Identify wireless security protocols from packet captures
- Recognize attack signatures in network traffic
- Evaluate wireless network security posture
- Recommend appropriate security controls for different environments
- Understand the impact of various wireless vulnerabilities
