# OT Hacking Methodology

## Gathering Default Passwords Using CIRT.net

The Computer Incident Response Team (CIRT) maintains comprehensive databases of default passwords for industrial and network devices.

### CIRT Default Password Database
- **URL**: https://cirt.net/passwords
- **Coverage**: Over 3,000 default passwords for various devices
- **Categories**: Network devices, industrial equipment, operating systems
- **Search Functions**: Search by vendor, product, or device type

### Using CIRT for OT Security
1. **Device Identification**: First identify the manufacturer and model of OT devices
2. **Database Search**: Search CIRT database for matching device entries
3. **Credential Testing**: Test discovered default credentials against target systems
4. **Documentation**: Record findings for vulnerability assessment reports

### Common OT Device Default Credentials
- **Siemens PLCs**: admin/admin, Administrator/(blank)
- **Allen-Bradley**: admin/(blank), user/user
- **Schneider Electric**: admin/admin, USER/USER
- **GE Fanuc**: admin/(blank), Administrator/Administrator
- **Modicon**: admin/(blank), USER/USER

### CIRT Database Limitations
- **Update Frequency**: Database may not include latest device models
- **Vendor Changes**: Manufacturers may change default credentials
- **Regional Variations**: Different defaults for different markets
- **Custom Configurations**: Some devices may have customer-specific defaults

## Information Gathering Tools

### Kamerka-GUI

Advanced search engine for internet-connected devices with GUI interface.

#### Features and Capabilities
- **Web Interface**: User-friendly graphical interface for device discovery
- **Search Filters**: Filter by country, device type, protocol, and vendor
- **Real-Time Results**: Live search results from multiple data sources
- **Export Functions**: Export results in various formats (CSV, JSON, XML)

#### OT-Specific Searches
```bash
# Common OT device searches in Kamerka
- Modbus: port:502
- DNP3: port:20000
- EtherNet/IP: port:44818
- BACnet: port:47808
- Crimson V3: port:789
```

#### Using Kamerka for OT Reconnaissance
1. **Target Selection**: Define geographic or network scope
2. **Protocol Filtering**: Search for specific industrial protocols
3. **Device Enumeration**: Identify accessible OT devices
4. **Vulnerability Assessment**: Check for default credentials and open services

### Zeek (formerly Bro)

Network security monitoring platform for analyzing OT traffic.

#### OT Protocol Analysis
- **Modbus Analysis**: Deep packet inspection of Modbus TCP/RTU traffic
- **DNP3 Support**: Parsing and analysis of DNP3 communications
- **Custom Protocols**: Scripting support for proprietary protocols
- **Anomaly Detection**: Behavioral analysis of OT communications

#### Zeek Configuration for OT Networks
```bash
# Enable OT protocol analyzers
@load protocols/modbus
@load protocols/dnp3
@load protocols/s7comm

# Custom OT monitoring script
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
    print fmt("Modbus communication: %s -> %s", c$id$orig_h, c$id$resp_h);
}
```

#### OT Security Monitoring
- **Traffic Baseline**: Establish normal communication patterns
- **Anomaly Detection**: Identify unusual or suspicious activities
- **Protocol Violations**: Detect malformed or invalid protocol messages
- **Command Monitoring**: Track critical control commands and responses

### Crimson IP

Specialized search engine for discovering industrial control systems.

#### Search Capabilities
- **ICS Device Discovery**: Focused on industrial control systems
- **Protocol Identification**: Automatic protocol detection and classification
- **Vulnerability Mapping**: Links discovered devices to known vulnerabilities
- **Geographic Mapping**: Visual representation of device locations

#### OT Device Categories
- **Power Systems**: SCADA systems, smart grid components
- **Manufacturing**: PLCs, HMIs, industrial robots
- **Building Automation**: HVAC systems, lighting controls
- **Transportation**: Traffic management, railway systems

#### Search Methodology
1. **Initial Scan**: Broad search for OT devices in target region
2. **Protocol Filtering**: Focus on specific industrial protocols
3. **Device Classification**: Categorize discovered devices by type and function
4. **Vulnerability Research**: Research known vulnerabilities for identified devices

### ZoomEye

Comprehensive search engine for internet-connected devices and services.

#### OT-Specific Features
- **Industrial Filters**: Pre-defined filters for OT device types
- **Protocol Search**: Search by specific industrial protocols
- **Vendor Categorization**: Group results by device manufacturer
- **API Access**: Programmatic access for automated reconnaissance

#### Common OT Searches
```bash
# ZoomEye search queries for OT systems
app:"Modbus"
port:502
service:"dnp3"
device:"PLC"
title:"HMI"
banner:"SCADA"
```

#### Advanced Search Techniques
- **Boolean Operators**: Combine multiple search criteria
- **Geographic Filtering**: Limit searches to specific countries or regions
- **Time-Based Searches**: Find recently discovered devices
- **SSL Certificate Analysis**: Identify devices by SSL certificate characteristics

### OHLYPHE

Open-source intelligence gathering tool for OT environments.

#### Functionality
- **Multi-Source Aggregation**: Combines data from multiple search engines
- **Automated Reporting**: Generates comprehensive reconnaissance reports
- **Custom Queries**: Support for user-defined search parameters
- **Data Correlation**: Links related devices and systems

#### OT Intelligence Gathering
- **Asset Discovery**: Identify all accessible OT devices in target networks
- **Vendor Analysis**: Catalog devices by manufacturer and model
- **Vulnerability Mapping**: Correlate discovered devices with CVE databases
- **Network Topology**: Map relationships between discovered systems

## Information Gathering and Scanning ICS/SCADA Systems Using Nmap

### Nmap for OT Reconnaissance

Network Mapper (Nmap) with specialized scripts for industrial control systems.

#### OT-Specific NSE Scripts
```bash
# Install NSE scripts for OT scanning
nmap --script-updatedb

# Common OT NSE scripts
modbus-discover.nse          # Modbus device discovery
s7-info.nse                 # Siemens S7 PLC information
enip-info.nse               # EtherNet/IP device information
bacnet-info.nse             # BACnet device discovery
dnp3-info.nse               # DNP3 system information
```

#### Modbus Scanning Techniques
```bash
# Basic Modbus discovery
nmap -p 502 --script modbus-discover <target>

# Modbus device enumeration
nmap -p 502 --script modbus-discover,modbus-enumerate <target>

# Detailed Modbus analysis
nmap -p 502 --script modbus-discover,modbus-enumerate,modbus-function-codes <target>
```

#### Siemens S7 PLC Scanning
```bash
# S7 PLC identification
nmap -p 102 --script s7-info <target>

# S7 device enumeration  
nmap -p 102 --script s7-info,s7-enum <target>

# S7 vulnerability scanning
nmap -p 102 --script s7-info,s7-enum,s7-vuln-check <target>
```

#### EtherNet/IP Scanning
```bash
# EtherNet/IP device discovery
nmap -p 44818 --script enip-info <target>

# CIP (Common Industrial Protocol) enumeration
nmap -p 44818 --script enip-info,enip-enumerate <target>

# Allen-Bradley specific scanning
nmap -p 44818 --script enip-info,enip-enumerate,ab-enum <target>
```

#### BACnet Device Discovery
```bash
# BACnet device scanning
nmap -sU -p 47808 --script bacnet-info <target>

# BACnet object enumeration
nmap -sU -p 47808 --script bacnet-info,bacnet-discover-enumerate <target>
```

#### DNP3 System Scanning
```bash
# DNP3 system identification
nmap -p 20000 --script dnp3-info <target>

# DNP3 function enumeration
nmap -p 20000 --script dnp3-info,dnp3-enum <target>
```

### Safe Scanning Practices for OT
- **Non-Intrusive Scanning**: Use passive scanning techniques when possible
- **Timing Controls**: Implement delays between scan attempts
- **Limited Scope**: Restrict scanning to specific devices or networks
- **Change Windows**: Perform active scanning during maintenance windows

### Scan Result Analysis
1. **Device Identification**: Catalog discovered devices by type and function
2. **Protocol Analysis**: Document supported protocols and versions
3. **Security Assessment**: Identify potential security weaknesses
4. **Network Mapping**: Create topology diagrams of discovered systems

## Sniffing Using NetworkMiner

### NetworkMiner for OT Traffic Analysis

NetworkMiner is a Network Forensic Analysis Tool (NFAT) capable of analyzing industrial protocol traffic.

#### OT Protocol Support
- **Modbus TCP/RTU**: Complete parsing of Modbus communications
- **DNP3**: Analysis of DNP3 point data and control commands  
- **EtherNet/IP**: CIP message analysis and device communications
- **S7**: Siemens S7 protocol analysis and data extraction
- **Custom Protocols**: Extensible framework for proprietary protocols

#### Traffic Capture Setup
```bash
# Configure network interface for promiscuous mode
sudo ifconfig eth0 promisc

# Capture OT network traffic using tcpdump
sudo tcpdump -i eth0 -s 65535 -w ot_traffic.pcap

# Alternative using Wireshark command line
sudo tshark -i eth0 -w ot_traffic.pcap
```

#### NetworkMiner Analysis Features
- **Protocol Reconstruction**: Reassemble fragmented protocol messages
- **Device Fingerprinting**: Identify device types and manufacturers
- **Communication Patterns**: Analyze communication flows and relationships
- **Data Extraction**: Extract files, images, and configuration data

#### OT-Specific Analysis Techniques
1. **Baseline Establishment**: Capture normal operational traffic patterns
2. **Anomaly Detection**: Compare current traffic against established baselines
3. **Command Analysis**: Focus on control commands and responses
4. **Error Detection**: Identify protocol errors and malformed messages

### Analyzing Modbus Communications
- **Function Code Analysis**: Examine Modbus function codes and data
- **Register Mapping**: Map Modbus registers to physical processes
- **Exception Handling**: Identify Modbus exception responses
- **Timing Analysis**: Analyze communication timing and delays

### DNP3 Traffic Analysis
- **Object Variations**: Analyze different DNP3 object types and variations
- **Control Operations**: Monitor control commands and acknowledgments
- **Data Quality**: Examine data quality flags and timestamps
- **Authentication**: Analyze secure authentication exchanges

## Analyzing Modbus/TCP Traffic Using Wireshark

### Wireshark Modbus Analysis

Wireshark provides comprehensive support for Modbus protocol analysis.

#### Modbus Protocol Dissector Features
- **Automatic Detection**: Automatic protocol detection on port 502
- **Function Code Decoding**: Complete decoding of all Modbus function codes
- **Data Interpretation**: Intelligent interpretation of register and coil data
- **Error Analysis**: Detailed analysis of Modbus exception responses

#### Modbus Filter Expressions
```bash
# Basic Modbus traffic filtering
modbus

# Filter by function code
modbus.func_code == 3    # Read Holding Registers
modbus.func_code == 6    # Write Single Register
modbus.func_code == 16   # Write Multiple Registers

# Filter by register addresses
modbus.regnum16 >= 1000 && modbus.regnum16 <= 2000

# Filter by unit identifier
modbus.unit_id == 1

# Filter Modbus exceptions
modbus.exception_code
```

#### Advanced Modbus Analysis
```bash
# Identify write operations
modbus.func_code == 5 || modbus.func_code == 6 || modbus.func_code == 15 || modbus.func_code == 16

# Monitor specific register ranges
modbus.regnum16 >= 40001 && modbus.regnum16 <= 49999  # Input registers

# Detect rapid polling
frame.time_delta < 0.1 && modbus
```

### Modbus Security Analysis Techniques
1. **Authentication Assessment**: Check for authentication mechanisms
2. **Encryption Analysis**: Verify if communications are encrypted
3. **Command Monitoring**: Track critical control commands
4. **Anomaly Detection**: Identify unusual communication patterns

### Creating Custom Modbus Profiles
- **Device Fingerprinting**: Create profiles based on Modbus responses
- **Register Mapping**: Map Modbus registers to physical processes
- **Communication Patterns**: Document normal vs abnormal patterns
- **Security Baseline**: Establish security baselines for monitoring

## Vulnerability Scanning Using Nessus

### Nessus for OT Vulnerability Assessment

Nessus provides specialized plugins for scanning industrial control systems.

#### OT-Specific Nessus Plugins
- **Industrial Protocols**: Plugins for Modbus, DNP3, EtherNet/IP, S7
- **Device Identification**: Fingerprinting of industrial devices
- **Default Credentials**: Testing for default usernames and passwords
- **CVE Coverage**: Comprehensive coverage of OT-specific vulnerabilities

#### Configuring Nessus for OT Scanning
```bash
# Create OT-specific scan policy
1. Login to Nessus web interface
2. Navigate to Policies -> New Policy
3. Select "Industrial Control Systems" template
4. Configure scan settings for OT environment
5. Enable OT-specific plugin families
```

#### Safe OT Scanning Configuration
- **Network Discovery**: Use passive discovery methods when possible
- **Port Scanning**: Limit port scans to known industrial protocols
- **Timing Settings**: Configure slower scan speeds for OT networks
- **Exclusions**: Exclude critical production systems if necessary

#### OT Vulnerability Categories
1. **Default Credentials**: Unchanged default passwords on devices
2. **Unencrypted Communications**: Clear-text protocol implementations
3. **Missing Updates**: Devices missing critical security patches
4. **Weak Authentication**: Systems with inadequate access controls
5. **Protocol Vulnerabilities**: Flaws in industrial protocol implementations

### Interpreting Nessus OT Results
- **Risk Prioritization**: Focus on vulnerabilities affecting safety and availability
- **Asset Correlation**: Map vulnerabilities to specific industrial processes
- **Remediation Planning**: Develop remediation plans considering operational impact
- **Compliance Mapping**: Map findings to relevant compliance requirements

## Fuzzing ICS Protocols

### Fuzzowski

Modern protocol fuzzing framework designed for industrial control systems.

#### Fuzzowski Features
- **Multi-Protocol Support**: Built-in support for major industrial protocols
- **Intelligent Fuzzing**: Smart fuzzing based on protocol specifications
- **Session Management**: Maintains protocol session state during fuzzing
- **Crash Detection**: Automatic detection of target crashes and hangs

#### Installation and Setup
```bash
# Install Fuzzowski
git clone https://github.com/nccgroup/fuzzowski
cd fuzzowski
pip install -r requirements.txt

# Basic usage
python fuzzowski.py --help
```

#### Modbus Fuzzing with Fuzzowski
```python
# Modbus fuzzing script example
from fuzzowski import *

# Define target
target = Target(
    connection=TCPSocketConnection("192.168.1.100", 502),
    monitors=[ProcessMonitor("modbus_server")]
)

# Create Modbus session
s_initialize("modbus_read_holding_registers")
s_byte(0x00, name="transaction_id_1")  # Transaction ID
s_byte(0x01, name="transaction_id_2")
s_byte(0x00, name="protocol_id_1")     # Protocol ID
s_byte(0x00, name="protocol_id_2")
s_byte(0x00, name="length_1")          # Length
s_byte(0x06, name="length_2")
s_byte(0x01, name="unit_id")           # Unit ID
s_byte(0x03, name="function_code")     # Read Holding Registers
s_word(0x0000, name="starting_address") # Starting Address (FUZZ)
s_word(0x0001, name="quantity")        # Quantity (FUZZ)

# Start fuzzing
session.connect(s_get("modbus_read_holding_registers"))
session.fuzz()
```

#### DNP3 Fuzzing
```python
# DNP3 fuzzing configuration
s_initialize("dnp3_request")
s_byte(0x05, name="start1")        # Start bytes
s_byte(0x64, name="start2")
s_byte(0x05, name="length")        # Length (FUZZ)
s_byte(0x01, name="control")       # Control
s_word(0x0001, name="destination") # Destination (FUZZ)
s_word(0x0064, name="source")      # Source
s_word(0x0000, name="crc")         # CRC
```

#### Fuzzing Best Practices for OT
- **Isolated Environment**: Always fuzz in isolated test environments
- **Baseline Testing**: Establish normal behavior before fuzzing
- **Gradual Approach**: Start with simple fuzzing and increase complexity
- **Recovery Procedures**: Have procedures for recovering crashed systems

### Protocol Fuzzing Methodology
1. **Protocol Analysis**: Understand target protocol structure and behavior
2. **Test Environment**: Set up isolated fuzzing environment
3. **Baseline Establishment**: Document normal protocol behavior
4. **Fuzzing Strategy**: Develop systematic fuzzing approach
5. **Result Analysis**: Analyze crashes and unexpected behaviors
6. **Vulnerability Validation**: Confirm and validate discovered vulnerabilities

## Hacking ICS Hardware

### Hardware-Based Attack Vectors
- **Physical Access**: Direct access to industrial devices and panels
- **Serial Interfaces**: Exploitation of RS-232, RS-485 serial connections
- **Debug Ports**: JTAG, UART, and other debug interfaces
- **Removable Media**: USB drives, SD cards, and other removable storage

### Hardware Analysis Techniques
- **Circuit Board Analysis**: Visual inspection and reverse engineering
- **Firmware Extraction**: Dumping firmware from flash memory chips
- **Signal Analysis**: Analyzing electrical signals and communications
- **Side-Channel Analysis**: Power consumption and electromagnetic emissions

### Physical Security Considerations
- **Enclosure Security**: Evaluation of physical protection mechanisms
- **Tamper Detection**: Assessment of tamper detection and response
- **Access Controls**: Physical access control and monitoring systems
- **Environmental Controls**: Protection against environmental threats

## Hacking Modbus Slaves Using Metasploit

### Metasploit Modbus Modules

Metasploit Framework includes several modules for Modbus exploitation.

#### Available Modbus Modules
```bash
# List Modbus-related modules
msf6 > search modbus

# Common Modbus modules
auxiliary/scanner/scada/modbusdetect    # Modbus device detection
auxiliary/scanner/scada/modbusclient    # Modbus client functionality  
auxiliary/dos/modbus/modbus_dos         # Modbus denial of service
exploit/windows/scada/modbus_stuxnet    # Stuxnet-style attack
```

#### Modbus Device Discovery
```bash
msf6 > use auxiliary/scanner/scada/modbusdetect
msf6 auxiliary(scanner/scada/modbusdetect) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/scada/modbusdetect) > set RPORT 502
msf6 auxiliary(scanner/scada/modbusdetect) > run
```

#### Modbus Data Reading
```bash
msf6 > use auxiliary/scanner/scada/modbusclient
msf6 auxiliary(scanner/scada/modbusclient) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/scada/modbusclient) > set FUNCTION READ_HOLDING_REGISTERS
msf6 auxiliary(scanner/scada/modbusclient) > set DATA_ADDRESS 1000
msf6 auxiliary(scanner/scada/modbusclient) > set NUMBER 10
msf6 auxiliary(scanner/scada/modbusclient) > run
```

#### Modbus Data Writing
```bash
msf6 > use auxiliary/scanner/scada/modbusclient
msf6 auxiliary(scanner/scada/modbusclient) > set RHOSTS 192.168.1.100
msf6 auxiliary(scanner/scada/modbusclient) > set FUNCTION WRITE_SINGLE_REGISTER
msf6 auxiliary(scanner/scada/modbusclient) > set DATA_ADDRESS 2000
msf6 auxiliary(scanner/scada/modbusclient) > set DATA 12345
msf6 auxiliary(scanner/scada/modbusclient) > run
```

### Modbus Attack Scenarios
- **Data Manipulation**: Altering process variables and setpoints
- **Denial of Service**: Flooding Modbus networks with requests
- **Device Impersonation**: Responding as legitimate Modbus devices
- **Man-in-the-Middle**: Intercepting and modifying Modbus communications

## Hacking PLC Using Modbus-CLI

### Modbus-CLI Tool

Command-line interface for interacting with Modbus devices.

#### Installation
```bash
# Install modbus-cli
pip install modbus-cli

# Alternative installation from source
git clone https://github.com/tallakt/modbus-cli
cd modbus-cli
pip install .
```

#### Basic Usage
```bash
# Read holding registers
modbus -h 192.168.1.100 -p 502 -u 1 read_holding_registers 1000 10

# Read input registers  
modbus -h 192.168.1.100 -p 502 -u 1 read_input_registers 3000 5

# Write single register
modbus -h 192.168.1.100 -p 502 -u 1 write_single_register 2000 12345

# Write multiple registers
modbus -h 192.168.1.100 -p 502 -u 1 write_multiple_registers 2000 100 200 300
```

#### Advanced PLC Interactions
```bash
# Read coil status
modbus -h 192.168.1.100 -p 502 -u 1 read_coils 0 16

# Write coil values
modbus -h 192.168.1.100 -p 502 -u 1 write_single_coil 10 1

# Read discrete inputs
modbus -h 192.168.1.100 -p 502 -u 1 read_discrete_inputs 100 8

# Diagnostic functions
modbus -h 192.168.1.100 -p 502 -u 1 diagnostic 0x0000 0x0001
```

### PLC Attack Techniques
- **Register Scanning**: Systematically reading all accessible registers
- **Function Code Testing**: Testing all supported Modbus function codes  
- **Boundary Testing**: Testing register address boundaries
- **Exception Generation**: Deliberately generating Modbus exceptions

### Automation Scripts
```bash
#!/bin/bash
# Automated PLC reconnaissance script

HOST="192.168.1.100"
UNIT=1

echo "Scanning PLC at $HOST"

# Test connectivity
modbus -h $HOST -u $UNIT read_holding_registers 0 1 >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "PLC is accessible"
    
    # Read device identification
    echo "Device Information:"
    modbus -h $HOST -u $UNIT read_device_identification
    
    # Scan holding registers
    echo "Scanning holding registers..."
    for addr in {0..100}; do
        result=$(modbus -h $HOST -u $UNIT read_holding_registers $addr 1 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "Register $addr: $result"
        fi
    done
else
    echo "PLC is not accessible"
fi
```

## Gaining Remote Access Using DNP3

### DNP3 Protocol Exploitation

DNP3 (Distributed Network Protocol 3) is commonly used in utility SCADA systems.

#### DNP3 Communication Structure
- **Application Layer**: Data objects and function codes
- **Transport Layer**: Segmentation and reassembly
- **Data Link Layer**: Frame structure and error detection
- **Physical Layer**: Serial or TCP/IP communications

#### DNP3 Attack Vectors
- **Authentication Bypass**: Exploiting weak or missing authentication
- **Data Manipulation**: Altering control points and analog values
- **Replay Attacks**: Replaying captured DNP3 commands
- **Denial of Service**: Flooding with malformed DNP3 frames

### DNP3 Exploitation Tools
```bash
# Using nmap for DNP3 discovery
nmap -p 20000 --script dnp3-info <target>

# Custom DNP3 client for exploitation
python dnp3_exploit.py --target 192.168.1.100 --port 20000
```

### DNP3 Attack Scenarios
1. **Unauthorized Control**: Sending unsolicited control commands
2. **Data Injection**: Injecting false measurement data
3. **Configuration Changes**: Modifying DNP3 device configurations
4. **Session Hijacking**: Taking over legitimate DNP3 sessions

---

## Key CEH v13 Exam Points

### Critical Concepts
1. **Reconnaissance Methodology**: Understand systematic approach to OT information gathering
2. **Protocol-Specific Tools**: Master tools for different industrial protocols (Modbus, DNP3, S7)
3. **Safe Scanning Practices**: Know how to scan OT networks without causing disruption
4. **Traffic Analysis**: Understand how to analyze industrial protocol communications
5. **Vulnerability Assessment**: Know how to safely assess OT vulnerabilities
6. **Fuzzing Techniques**: Understand protocol fuzzing for vulnerability discovery
7. **Hardware Exploitation**: Recognize hardware-based attack vectors

### Exam Focus Areas
- **Information Gathering Tools**: Kamerka, Zeek, Crimson IP, ZoomEye capabilities
- **Nmap OT Scripts**: Knowledge of industrial NSE scripts and their usage
- **Modbus Analysis**: Deep understanding of Modbus protocol exploitation
- **DNP3 Exploitation**: Techniques for attacking DNP3 implementations
- **Vulnerability Scanning**: Safe practices for OT vulnerability assessment
- **Protocol Fuzzing**: Understanding of fuzzing methodologies and tools
- **Traffic Analysis**: Skills in analyzing industrial network communications
- **Hardware Attacks**: Recognition of physical attack vectors

### Practical Skills
- Execute safe reconnaissance against OT networks
- Use specialized tools for industrial protocol analysis  
- Identify vulnerabilities without disrupting operations
- Analyze captured OT network traffic for security issues
- Conduct protocol fuzzing in controlled environments
- Exploit common OT vulnerabilities using appropriate tools
- Understand the operational impact of various attack techniques
