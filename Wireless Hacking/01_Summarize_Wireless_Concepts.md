# Wireless Concepts - CEH v13 Module 16

## Table of Contents
1. [Wireless Terminologies](#wireless-terminologies)
2. [Types of Wireless Networks](#types-of-wireless-networks)
3. [Wireless Standards](#wireless-standards)
4. [WiFi Authentication Process](#wifi-authentication-process)
5. [Types of Wireless Antennas](#types-of-wireless-antennas)

---

## 1. Wireless Terminologies

### GSM (Global System for Mobile Communications)
- **Definition**: A standard developed to describe the protocols for second-generation (2G) digital cellular networks
- **Key Features**:
  - Uses TDMA (Time Division Multiple Access) technology
  - Operates in 900 MHz and 1800 MHz frequency bands
  - Provides voice and data services
  - Foundation for modern mobile communication systems

### Bandwidth
- **Definition**: The range of frequencies available for transmitting data in a communication system
- **Measurement**: Expressed in Hertz (Hz), typically in MHz or GHz for wireless
- **Impact**: Higher bandwidth allows for faster data transmission rates
- **Common WiFi Bandwidths**:
  - 20 MHz (standard)
  - 40 MHz (802.11n)
  - 80 MHz, 160 MHz (802.11ac/ax)

### Access Point (AP)
- **Definition**: A networking hardware device that allows WiFi-capable devices to connect to a wired network
- **Functions**:
  - Acts as a bridge between wireless and wired networks
  - Manages wireless client connections
  - Implements security protocols
  - Controls network access and traffic flow
- **Types**: Standalone, controller-based, cloud-managed

### BSSID (Basic Service Set Identifier)
- **Definition**: A unique 48-bit identifier for a wireless access point
- **Format**: MAC address format (XX:XX:XX:XX:XX:XX)
- **Purpose**:
  - Distinguishes between different access points
  - Used in wireless frame headers
  - Essential for roaming and handoff processes
- **Relationship**: Multiple SSIDs can share the same BSSID

### ISM (Industrial, Scientific, and Medical)
- **Definition**: Radio frequency bands reserved internationally for industrial, scientific, and medical purposes
- **Key ISM Bands for WiFi**:
  - 2.4 GHz (2.400-2.485 GHz)
  - 5 GHz (5.725-5.875 GHz)
- **Characteristics**:
  - License-free operation
  - Subject to interference from other devices
  - Regulated power limits

### Hotspot
- **Definition**: A physical location where users can access the internet wirelessly
- **Types**:
  - **Public Hotspots**: Coffee shops, airports, hotels
  - **Private Hotspots**: Personal mobile hotspots, home networks
  - **Commercial Hotspots**: Paid access points
- **Security Considerations**: Often unsecured or use weak authentication

### Association
- **Definition**: The process by which a wireless device connects to an access point
- **Association Process**:
  1. **Probe Request/Response**: Device discovers available networks
  2. **Authentication**: Device authenticates with AP
  3. **Association Request/Response**: Device requests to join network
  4. **Four-Way Handshake**: Encryption keys are established (WPA/WPA2)
- **Association States**: Not authenticated, authenticated but not associated, authenticated and associated

### SSID (Service Set Identifier)
- **Definition**: A human-readable name that identifies a wireless network
- **Characteristics**:
  - Up to 32 characters long
  - Case-sensitive
  - Can be hidden (not broadcasted in beacon frames)
- **Security Note**: SSID hiding is not a security measure as it can be easily discovered

### OFDM (Orthogonal Frequency Division Multiplexing)
- **Definition**: A digital modulation technique that divides data across multiple subcarriers
- **Advantages**:
  - Resistant to interference
  - Efficient spectrum usage
  - Reduces multipath fading effects
- **Usage**: Core technology in 802.11a/g/n/ac/ax standards
- **Subcarriers**: Typically 64 subcarriers in WiFi implementations

### MIMO-OFDM (Multiple Input, Multiple Output - OFDM)
- **Definition**: Combines MIMO antenna technology with OFDM modulation
- **Benefits**:
  - Increased data throughput
  - Improved signal quality
  - Better range and coverage
- **Implementations**:
  - 2x2 MIMO: 2 transmit, 2 receive antennas
  - 4x4 MIMO: 4 transmit, 4 receive antennas
  - MU-MIMO: Multi-user MIMO (802.11ac Wave 2)

### DSSS (Direct Sequence Spread Spectrum)
- **Definition**: A spread spectrum technique where data is multiplied by a pseudo-random code
- **Characteristics**:
  - Spreads signal over wider bandwidth
  - Provides interference resistance
  - Used in 802.11b standard
- **Chipping Rate**: 11 Mbps chipping rate for 802.11b
- **Processing Gain**: Ratio of spread bandwidth to original signal bandwidth

### FHSS (Frequency Hopping Spread Spectrum)
- **Definition**: A spread spectrum technique that rapidly switches frequencies in a predetermined pattern
- **Operation**:
  - Transmits on different frequencies in sequence
  - Receiver follows the same hopping pattern
  - Provides resistance to jamming and interference
- **Historical Usage**: Original 802.11 standard, Bluetooth
- **Hopping Rate**: Typically 1600 hops per second

---

## 2. Types of Wireless Networks

### Extension to Wireless Networks
<img width="821" height="453" alt="image" src="https://github.com/user-attachments/assets/6af619a0-030b-43e4-a4f8-b4eb4dcc37dd" />

#### Software APs
- **Definition**: Software-based access points running on general-purpose hardware
- **Characteristics**:
  - Cost-effective solution
  - Flexible configuration options
  - Can run on standard computers or servers
- **Examples**:
  - hostapd on Linux
  - Windows Internet Connection Sharing
  - Virtual APs on laptops
- **Limitations**: Performance depends on host hardware capabilities

#### Hardware APs
- **Definition**: Dedicated hardware devices designed specifically for wireless networking
- **Advantages**:
  - Optimized performance
  - Purpose-built antenna designs
  - Enterprise-grade features
  - Better heat dissipation and reliability
- **Types**:
  - Consumer-grade routers
  - Enterprise access points
  - Outdoor/weatherproof models
- **Features**: Power over Ethernet (PoE), multiple radio support, advanced security

### Multiple Wireless Networks
<img width="821" height="448" alt="image" src="https://github.com/user-attachments/assets/c1485fdb-d525-4979-b78e-cdf1772a57fe" />

- **Definition**: Deployment scenarios involving multiple interconnected wireless networks
- **Configurations**:
  - **Mesh Networks**: Self-forming, self-healing network topology
  - **Repeater/Extender Networks**: Signal amplification and coverage extension
  - **Bridge Networks**: Connecting separated network segments wirelessly
- **Management Considerations**:
  - Channel planning to avoid interference
  - Roaming optimization
  - Load balancing across APs

### LAN-to-LAN Wireless Networks
<img width="801" height="401" alt="image" src="https://github.com/user-attachments/assets/cc201f0d-a689-4235-9d83-41a344c5e492" />

- **Definition**: Wireless connections that bridge separate local area networks
- **Use Cases**:
  - Connecting buildings without running cables
  - Temporary network extensions
  - Backup connectivity solutions
- **Implementation Methods**:
  - **Point-to-Point Links**: Direct wireless connection between two locations
  - **Point-to-Multipoint**: One central location serving multiple remote sites
- **Equipment**: High-gain directional antennas, bridge-mode access points

### 3G/4G/5G Hotspot
- **Definition**: Mobile internet sharing using cellular data connections
- **Evolution**:
  - **3G**: Up to 2 Mbps, basic data services
  - **4G/LTE**: Up to 100 Mbps, mobile broadband
  - **5G**: Up to 10 Gbps, ultra-low latency applications
- **Implementation**:
  - **Mobile Hotspot Devices**: Dedicated cellular routers
  - **Smartphone Tethering**: Sharing mobile data connection
  - **USB Modems**: Direct cellular connection to devices
- **Security Considerations**: Cellular network vulnerabilities, data usage monitoring

---

## 3. Wireless Standards

### IEEE 802.11 Family Overview

| Standard | Year | Frequency | Max Data Rate | Range | Key Features |
|----------|------|-----------|---------------|--------|--------------|
| 802.11 | 1997 | 2.4 GHz | 2 Mbps | 20m | Original standard, FHSS/DSSS |
| 802.11a | 1999 | 5 GHz | 54 Mbps | 35m | OFDM, less congested band |
| 802.11b | 1999 | 2.4 GHz | 11 Mbps | 38m | DSSS, widespread adoption |
| 802.11g | 2003 | 2.4 GHz | 54 Mbps | 38m | OFDM, backward compatible |
| 802.11n | 2009 | 2.4/5 GHz | 600 Mbps | 70m | MIMO, channel bonding |
| 802.11ac | 2013 | 5 GHz | 6.93 Gbps | 35m | MU-MIMO, wider channels |
| 802.11ax | 2019 | 2.4/5 GHz | 9.6 Gbps | 30m | OFDMA, improved efficiency |

### Key Standard Features

#### 802.11n (WiFi 4)
- **MIMO Technology**: Multiple antennas for improved performance
- **Channel Bonding**: Combines 20 MHz channels into 40 MHz
- **Spatial Streams**: Up to 4 spatial streams
- **Backward Compatibility**: Works with 802.11a/b/g devices

#### 802.11ac (WiFi 5)
- **5 GHz Only**: Reduces interference from 2.4 GHz devices
- **Wider Channels**: 80 MHz and 160 MHz channel widths
- **MU-MIMO**: Simultaneous transmission to multiple users
- **Beamforming**: Focused signal transmission

#### 802.11ax (WiFi 6/6E)
- **OFDMA**: Orthogonal Frequency Division Multiple Access
- **BSS Coloring**: Reduces interference in dense deployments
- **Target Wake Time**: Power saving for IoT devices
- **6 GHz Band**: WiFi 6E extends to 6 GHz spectrum

---

## 4. WiFi Authentication Process

### PSK (Pre-Shared Key) Authentication
<img width="987" height="267" alt="image" src="https://github.com/user-attachments/assets/253cea98-d9c3-430a-8424-899b8fe8b2b9" />

#### WPA-PSK Process
1. **Association**: Client associates with access point
2. **PSK Derivation**: 
   - PSK = PBKDF2(passphrase, SSID, 4096 iterations, 256 bits)
3. **Four-Way Handshake**:
   - **Message 1**: AP → Client (ANonce)
   - **Message 2**: Client → AP (SNonce, MIC)
   - **Message 3**: AP → Client (GTK, MIC)
   - **Message 4**: Client → AP (Acknowledgment)
4. **Key Hierarchy**:
   - **PMK** (Pairwise Master Key): Derived from PSK
   - **PTK** (Pairwise Transient Key): Session-specific encryption key
   - **GTK** (Group Temporal Key): Multicast/broadcast traffic key

#### WPA2-PSK (AES-CCMP)
- **Encryption**: Advanced Encryption Standard (AES)
- **Integrity**: Counter Mode with CBC-MAC Protocol (CCMP)
- **Key Length**: 128-bit AES keys
- **Security**: Significantly stronger than WEP and original WPA

#### WPA3-PSK (SAE)
- **SAE**: Simultaneous Authentication of Equals
- **Forward Secrecy**: Each session uses unique keys
- **Resistance**: Protection against offline dictionary attacks
- **Dragonfly Handshake**: Replaces four-way handshake vulnerabilities

### Centralized Authentication Mode
<img width="1041" height="496" alt="image" src="https://github.com/user-attachments/assets/7d0f0b91-3e67-4da5-9f5f-7073bb0f56e7" />

#### 802.1X/EAP Framework
- **Components**:
  - **Supplicant**: Client device requesting network access
  - **Authenticator**: Access point or network switch
  - **Authentication Server**: RADIUS server with user database

#### Common EAP Methods

##### EAP-TLS (Transport Layer Security)
- **Security**: Mutual certificate authentication
- **Requirements**: PKI infrastructure, client certificates
- **Process**:
  1. TLS handshake establishment
  2. Certificate exchange and validation
  3. Key derivation and distribution
- **Advantages**: Strongest security, no password transmission

##### PEAP (Protected EAP)
- **Operation**: Creates secure TLS tunnel for inner authentication
- **Common Inner Methods**:
  - **MS-CHAPv2**: Microsoft Challenge Handshake Authentication
  - **EAP-GTC**: Generic Token Card
- **Benefits**: Protects against eavesdropping, easier deployment than EAP-TLS

##### EAP-TTLS (Tunneled TLS)
- **Flexibility**: Supports various inner authentication methods
- **Inner Methods**: PAP, CHAP, MS-CHAP, MS-CHAPv2
- **Advantages**: Legacy authentication support, strong security

#### RADIUS Authentication Flow
1. **Association**: Client associates with access point
2. **EAP Identity Request/Response**: AP requests client identity
3. **RADIUS Access-Request**: AP forwards credentials to RADIUS server
4. **Authentication Exchange**: EAP method-specific authentication
5. **RADIUS Access-Accept/Reject**: Server decision
6. **Key Distribution**: Encryption keys provided to client and AP

---

## 5. Types of Wireless Antennas

### Directional Antenna
- **Characteristics**:
  - Focused radio frequency energy in specific direction
  - Higher gain in targeted direction
  - Reduced coverage area but increased range
- **Applications**:
  - Point-to-point links
  - Long-distance wireless bridges
  - Reducing interference from unwanted directions
- **Typical Gain**: 12-24 dBi
- **Beamwidth**: Narrow horizontal and vertical coverage patterns

### Omnidirectional Antenna
- **Characteristics**:
  - Radiates RF energy equally in all horizontal directions
  - Circular coverage pattern (donut-shaped in 3D)
  - Lower gain but broader coverage
- **Applications**:
  - General access point coverage
  - Mobile device communications
  - Areas requiring 360-degree coverage
- **Typical Gain**: 2-12 dBi
- **Pattern**: Uniform horizontal radiation, focused vertical pattern

### Parabolic Grid Antenna
- **Design**:
  - Parabolic reflector with grid construction
  - Feed element at focal point
  - Lightweight compared to solid dish antennas
- **Characteristics**:
  - Very high gain (typically 24-30 dBi)
  - Narrow beamwidth (8-15 degrees)
  - Excellent for long-distance point-to-point links
- **Advantages**:
  - High directivity
  - Wind resistance due to grid design
  - Cost-effective for high-gain applications

### Yagi Antenna
- **Construction**:
  - **Driven Element**: Connected to transmission line
  - **Reflector**: Element behind driven element
  - **Directors**: Elements in front of driven element
- **Characteristics**:
  - Moderate to high gain (6-20 dBi)
  - Directional radiation pattern
  - Relatively narrow beamwidth
- **Applications**:
  - Point-to-point communications
  - Extending wireless coverage in specific direction
  - TV and radio reception

### Dipole Antenna
- **Basic Design**:
  - Two conductive elements (typically quarter-wavelength each)
  - Fed at the center point
  - Simplest form of antenna
- **Characteristics**:
  - Omnidirectional in horizontal plane
  - Theoretical gain: 2.15 dBi
  - Resonant at specific frequencies
- **Types**:
  - **Half-Wave Dipole**: Most common configuration
  - **Folded Dipole**: Higher input impedance
  - **Inverted-V Dipole**: Bent configuration for space constraints

### Reflector Antenna
- **Principle**:
  - Uses reflective surface to direct radio waves
  - Feed antenna illuminates reflector surface
  - Reflector focuses energy in desired direction
- **Types**:
  - **Parabolic Reflector**: Curved surface for point focus
  - **Corner Reflector**: 90-degree angled surfaces
  - **Flat Panel**: Planar reflective surface with integrated feed
- **Applications**:
  - Satellite communications
  - Point-to-point microwave links
  - Radar systems
- **Advantages**: High gain, excellent directivity, interference rejection

### Antenna Parameters Summary

| Parameter | Definition | Impact |
|-----------|------------|--------|
| **Gain** | Measure of antenna's ability to direct RF energy | Higher gain = more focused energy, longer range |
| **Beamwidth** | Angular width of main radiation lobe | Narrower beam = more directional |
| **VSWR** | Voltage Standing Wave Ratio | Lower VSWR = better impedance matching |
| **Polarization** | Orientation of electric field | Must match for optimal communication |
| **Bandwidth** | Range of frequencies with acceptable performance | Wider bandwidth = more versatile |

---

## Key Security Implications

### Antenna Selection Impact on Security
- **Directional antennas** can limit signal leakage and eavesdropping
- **Omnidirectional antennas** may extend attack surface beyond intended coverage
- **High-gain antennas** can be detected from greater distances
- **Proper antenna placement** is crucial for both coverage and security

### Authentication Vulnerabilities
- **PSK-based networks** vulnerable to brute force attacks on captured handshakes
- **Open authentication** provides no security (WEP)
- **Enterprise authentication** more secure but complex to implement
- **WPS** (WiFi Protected Setup) introduces significant vulnerabilities

### Frequency Band Considerations
- **2.4 GHz**: More crowded, prone to interference, better penetration
- **5 GHz**: Less crowded, more bandwidth, shorter range
- **6 GHz**: Newest band, least crowded, WiFi 6E requirement
