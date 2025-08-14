# SNMP Enumeration

## Definition

SNMP (Simple Network Management Protocol) Enumeration is a network reconnaissance technique that exploits the SNMP protocol to extract valuable information from network devices, servers, and workstations. SNMP operates on UDP port 161 for queries and UDP port 162 for traps. This enumeration method allows attackers to gather system information, network configuration details, running processes, and other sensitive data using SNMP community strings and Management Information Base (MIB) queries.

## How SNMP Enumeration Works

### Basic Process:
1. **Port Discovery** - Scan for SNMP service on UDP port 161
2. **Community String Testing** - Test default and common community strings
3. **SNMP Version Detection** - Identify SNMP version (v1, v2c, v3)
4. **MIB Walking** - Query Management Information Base objects
5. **Information Extraction** - Collect system and network details
6. **Data Analysis** - Analyze gathered information for vulnerabilities

### SNMP Components:
- **SNMP Agent**: Software running on managed devices
- **SNMP Manager**: Management station performing queries
- **MIB (Management Information Base)**: Database of manageable objects
- **Community Strings**: Authentication mechanism (v1/v2c)
- **OID (Object Identifier)**: Unique identifier for MIB objects

## SNMP Versions and Ports

| Version | Port | Protocol | Security Features |
|---------|------|----------|-------------------|
| SNMPv1  | 161  | UDP      | Community strings only |
| SNMPv2c | 161  | UDP      | Community strings, bulk operations |
| SNMPv3  | 161  | UDP      | Authentication and encryption |
| SNMP Traps | 162 | UDP   | Asynchronous notifications |

## Common Community Strings

### Default Community Strings:
- **public** - Default read-only community string
- **private** - Default read-write community string
- **admin** - Administrative community string
- **manager** - Management community string
- **monitor** - Monitoring community string

### Vendor-Specific Strings:
- **cisco** - Cisco equipment default
- **hp** - HP/HPE equipment default
- **dell** - Dell equipment default
- **netman** - Network management systems
- **secret** - Alternative administrative string

## Important MIB Objects (OIDs)

| OID | Description | Information |
|-----|-------------|-------------|
| 1.3.6.1.2.1.1.1.0 | sysDescr | System description |
| 1.3.6.1.2.1.1.3.0 | sysUpTime | System uptime |
| 1.3.6.1.2.1.1.4.0 | sysContact | System contact |
| 1.3.6.1.2.1.1.5.0 | sysName | System name |
| 1.3.6.1.2.1.1.6.0 | sysLocation | System location |
| 1.3.6.1.2.1.2.2.1.1 | ifIndex | Network interface index |
| 1.3.6.1.2.1.2.2.1.2 | ifDescr | Interface descriptions |
| 1.3.6.1.2.1.25.1.6.0 | hrSystemProcesses | Number of processes |
| 1.3.6.1.2.1.25.4.2.1.2 | hrSWRunName | Running processes |
| 1.3.6.1.2.1.6.13.1.3 | tcpConnRemAddress | TCP connections |

## Tools and Commands

### SNMPwalk
```bash
# Basic SNMP walk
snmpwalk -v2c -c public target_ip

# Walk specific OID
snmpwalk -v2c -c public target_ip 1.3.6.1.2.1.1

# SNMP v1 walk
snmpwalk -v1 -c public target_ip

# Custom community string
snmpwalk -v2c -c private target_ip

# Walk with timeout
snmpwalk -t 10 -v2c -c public target_ip
```

### SNMPget
```bash
# Get specific OID
snmpget -v2c -c public target_ip 1.3.6.1.2.1.1.1.0

# Get multiple OIDs
snmpget -v2c -c public target_ip 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.5.0

# Get with different version
snmpget -v1 -c public target_ip 1.3.6.1.2.1.1.1.0
```

### Onesixtyone
```bash
# Fast SNMP scanner
onesixtyone target_ip

# Scan with custom community list
onesixtyone -c community.txt target_ip

# Scan IP range
onesixtyone -c community.txt 192.168.1.0/24

# Dictionary attack
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt target_ip
```

### Nmap SNMP Scripts
```bash
# SNMP info enumeration
nmap -sU -p 161 --script snmp-info target_ip

# SNMP process enumeration
nmap -sU -p 161 --script snmp-processes target_ip

# SNMP interface enumeration
nmap -sU -p 161 --script snmp-interfaces target_ip

# SNMP system info
nmap -sU -p 161 --script snmp-sysdescr target_ip

# All SNMP scripts
nmap -sU -p 161 --script snmp-* target_ip
```

### SNMPcheck
```bash
# Comprehensive SNMP enumeration
snmpcheck -t target_ip

# Custom community string
snmpcheck -t target_ip -c private

# Specify SNMP version
snmpcheck -t target_ip -v 2c

# Write output to file
snmpcheck -t target_ip -w
```

### Metasploit SNMP Modules
```bash
# SNMP login scanner
use auxiliary/scanner/snmp/snmp_login
set RHOSTS target_ip
run

# SNMP enumeration
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS target_ip
set COMMUNITY public
run

# SNMP enum shares
use auxiliary/scanner/snmp/snmp_enumshares
set RHOSTS target_ip
run
```

## Information Disclosure

### System Information:
- **Operating System**: OS type, version, and patch level
- **Hardware Details**: CPU, memory, storage information
- **System Uptime**: How long system has been running
- **Contact Information**: Administrator contact details
- **Location Data**: Physical system location

### Network Information:
- **Network Interfaces**: Interface configurations and statistics
- **Routing Tables**: Network routing information
- **ARP Tables**: Address resolution mappings
- **TCP/UDP Connections**: Active network connections
- **Network Services**: Running network services and ports

### Process Information:
- **Running Processes**: List of active processes
- **Process Details**: Process names, IDs, and resource usage
- **Installed Software**: Software packages and versions
- **Service Information**: System services and their status

### Security Information:
- **User Accounts**: Local user account information
- **Installed Software**: Vulnerability assessment data
- **File System**: Disk usage and file system information
- **Log Files**: System and security log entries

## Advantages

- **Rich Information**: Comprehensive system and network data
- **Standard Protocol**: SNMP widely implemented across devices
- **Remote Access**: Query devices remotely without local access
- **Structured Data**: Well-organized MIB structure
- **Multiple Tools**: Various enumeration tools available
- **Network Discovery**: Effective for mapping network infrastructure

## Limitations

- **Default Communities**: Many systems use default community strings
- **UDP Protocol**: Less reliable than TCP-based protocols
- **Version Differences**: Different capabilities across SNMP versions
- **Firewall Blocking**: SNMP ports commonly filtered
- **Authentication**: SNMPv3 requires proper authentication
- **Device Specific**: Some devices have limited SNMP implementation

## System Response Behaviors

### Network Equipment:
- **Routers**: Comprehensive routing and interface information
- **Switches**: Port configurations and VLAN information
- **Firewalls**: Security policies and connection data
- **Access Points**: Wireless configuration and client data

### Server Systems:
- **Windows Servers**: Process, service, and performance data
- **Linux Servers**: System statistics and configuration
- **Database Servers**: Connection and performance metrics
- **Web Servers**: Service status and configuration

### Security Configurations:
- **Default Settings**: Often use public/private community strings
- **Hardened Systems**: Custom community strings or SNMPv3
- **Enterprise Networks**: Centralized SNMP management
- **DMZ Systems**: May have SNMP disabled or restricted

## Security Implications

### Attack Vectors:
- **Information Gathering**: Detailed system reconnaissance
- **Network Mapping**: Understanding network topology
- **Service Discovery**: Identifying running services
- **Credential Harvesting**: Finding service accounts and passwords

### For Defenders:
- **Change Default Communities**: Use strong, unique community strings
- **Implement SNMPv3**: Use authentication and encryption
- **Access Controls**: Restrict SNMP access to management networks
- **Monitoring**: Log and monitor SNMP queries

### For Penetration Testers:
- **System Profiling**: Understand target system configurations
- **Network Analysis**: Map network infrastructure
- **Vulnerability Assessment**: Identify outdated software/services
- **Attack Planning**: Use gathered information for exploitation

## Detection and Response

### Detection Methods:
- **Network Monitoring**: Monitor UDP 161/162 traffic patterns
- **SNMP Logs**: Review SNMP agent logs for unusual queries
- **Community String Attempts**: Detect brute force attempts
- **IDS Signatures**: Identify SNMP enumeration tools

### Common Log Patterns:
```
# SNMP enumeration attempts
SNMP-AUTHFAIL: Authentication failure from 192.168.1.100
SNMP-QUERY: Excessive queries from single source
SNMP-WALK: MIB walking detected from 192.168.1.100

# Successful enumeration
SNMP-ACCESS: Community string 'public' accessed from 192.168.1.100
SNMP-READ: OID 1.3.6.1.2.1.1.1.0 queried from 192.168.1.100
```

## Practical Applications

### Network Management:
- **Device Monitoring**: Monitor network device performance
- **Configuration Management**: Retrieve device configurations
- **Fault Detection**: Identify network issues and failures
- **Capacity Planning**: Collect performance and usage data

### Security Assessment:
- **Asset Discovery**: Identify network devices and systems
- **Configuration Review**: Assess security configurations
- **Vulnerability Detection**: Find systems with security issues
- **Compliance Auditing**: Verify policy compliance

## CEH Exam Focus Points

- Understand SNMP versions (v1, v2c, v3) and their security features
- Know default community strings (public, private) and their risks
- Familiarize with common MIB objects and their OIDs
- Understand SNMP enumeration tools (snmpwalk, onesixtyone, nmap scripts)
- Know the difference between SNMP queries and traps
- Understand security implications of SNMP information disclosure
- Recognize proper SNMP hardening techniques (SNMPv3, access controls)
