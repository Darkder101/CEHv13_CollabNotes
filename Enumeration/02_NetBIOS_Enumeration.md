# NetBIOS Enumeration

## Definition

NetBIOS (Network Basic Input/Output System) Enumeration is a network reconnaissance technique used to gather information about Windows systems and network shares by exploiting the NetBIOS protocol. NetBIOS operates on ports 137 (UDP - Name Service), 138 (UDP - Datagram Service), and 139 (TCP - Session Service). This enumeration method allows attackers to discover hostnames, usernames, shares, services, and other critical system information without authentication.

## How NetBIOS Enumeration Works

### Basic Process:
1. **Port Scanning** - Identify systems with NetBIOS ports (137-139) open
2. **Name Table Query** - Request NetBIOS name table from target system
3. **Share Enumeration** - Discover available network shares and resources
4. **User Enumeration** - Extract user account information and SIDs
5. **Service Information** - Gather details about running services
6. **Session Establishment** - Attempt null sessions for further enumeration

### NetBIOS Name Types:
- **Unique Names**: Identify specific services or computers
- **Group Names**: Represent workgroups or domains
- **Computer Names**: Individual machine identifiers
- **Service Names**: Specific services running on systems

## NetBIOS Ports and Services

| Port | Protocol | Service | Description |
|------|----------|---------|-------------|
| 137  | UDP      | NetBIOS Name Service | Name registration and resolution |
| 138  | UDP      | NetBIOS Datagram Service | Connectionless communication |
| 139  | TCP      | NetBIOS Session Service | Connection-oriented communication |
| 445  | TCP      | SMB over IP | Direct SMB without NetBIOS layer |

## NetBIOS Name Suffixes

| Suffix | Type | Description |
|--------|------|-------------|
| 00     | Unique | Computer Name |
| 03     | Unique | Messenger Service |
| 06     | Unique | RAS Server Service |
| 1B     | Unique | Domain Master Browser |
| 1C     | Group  | Domain Controllers |
| 1D     | Unique | Master Browser |
| 1E     | Group  | Browser Service Elections |
| 20     | Unique | File Server Service |

## Tools and Commands

### Nbtstat (Windows)
```cmd
# Display NetBIOS name table
nbtstat -A target_ip

# Display local NetBIOS name cache
nbtstat -c

# Display NetBIOS names registered by broadcast
nbtstat -n

# Display NetBIOS name table with MAC addresses
nbtstat -a computername

# Continuous monitoring
nbtstat -A target_ip 5
```

### Nmblookup (Linux)
```bash
# Query NetBIOS name
nmblookup -A target_ip

# Find NetBIOS names in subnet
nmblookup '*'

# Query specific NetBIOS name type
nmblookup -M workgroup_name

# Find master browser
nmblookup -M - -d 2
```

### Smbclient
```bash
# List available shares
smbclient -L target_ip

# List shares with null session
smbclient -L target_ip -N

# Connect to specific share
smbclient //target_ip/sharename

# Anonymous connection attempt
smbclient -L target_ip -U ""
```

### Rpcclient
```bash
# Connect with null session
rpcclient -U "" target_ip

# Enumerate users
rpcclient $> enumdomusers

# Enumerate groups
rpcclient $> enumdomgroups

# Get user information
rpcclient $> queryuser username

# Get domain information
rpcclient $> querydominfo
```

### Enum4linux
```bash
# Full enumeration
enum4linux target_ip

# User enumeration only
enum4linux -U target_ip

# Share enumeration only
enum4linux -S target_ip

# Verbose enumeration
enum4linux -v target_ip

# All enumeration with RID cycling
enum4linux -a target_ip
```

### Nmap NetBIOS Scripts
```bash
# NetBIOS name discovery
nmap --script nbstat target_ip

# SMB enumeration
nmap --script smb-enum-shares target_ip

# SMB OS discovery
nmap --script smb-os-discovery target_ip

# SMB security mode
nmap --script smb-security-mode target_ip

# All SMB scripts
nmap --script smb-* target_ip
```

## Information Disclosure

### System Information:
- **Computer Names**: NetBIOS names and hostnames
- **Domain/Workgroup**: Domain membership information
- **Operating System**: OS version and build information
- **Services**: Running services and their versions
- **Network Shares**: Available file shares and permissions

### User Information:
- **User Accounts**: Local and domain user accounts
- **Groups**: Security groups and memberships
- **SIDs**: Security Identifiers for accounts
- **Login Information**: Last login times and account status
- **Password Policies**: Domain password requirements

### Network Information:
- **Network Topology**: Domain structure and trust relationships
- **Browser Elections**: Master browser and backup browsers
- **Service Announcements**: Advertised network services
- **Logon Servers**: Available domain controllers

## Advantages

- **No Authentication Required**: Many queries work with null sessions
- **Rich Information**: Provides comprehensive system details
- **Standard Protocol**: NetBIOS is widely implemented on Windows
- **Multiple Tools**: Various enumeration tools available
- **Network Discovery**: Effective for mapping Windows networks
- **Privilege Escalation**: Information aids in further exploitation

## Limitations

- **Windows Specific**: Primarily targets Windows systems
- **Security Improvements**: Modern systems have better protections
- **Firewall Blocking**: NetBIOS ports commonly filtered
- **SMBv1 Deprecation**: Newer systems disable legacy SMB versions
- **False Negatives**: Systems may not respond to queries
- **Detection Risk**: Activities can be logged and monitored

## System Response Behaviors

### Windows Versions:
- **Windows XP/2003**: Full NetBIOS support, often vulnerable
- **Windows 7/2008**: Improved security, selective responses
- **Windows 10/2019**: Enhanced protections, limited enumeration
- **Domain Controllers**: May provide extensive domain information

### Security Configurations:
- **Default Settings**: Often allow basic enumeration
- **Hardened Systems**: Restricted or disabled NetBIOS
- **Domain Policies**: Group policies may limit exposure
- **Network Isolation**: VLANs may restrict NetBIOS broadcasts

## Security Implications

### Attack Vectors:
- **Information Gathering**: Reconnaissance for targeted attacks
- **User Enumeration**: Building lists for password attacks
- **Share Access**: Discovering accessible network resources
- **Privilege Mapping**: Understanding user roles and permissions

### For Defenders:
- **Disable NetBIOS**: Turn off unnecessary NetBIOS services
- **Firewall Rules**: Block NetBIOS ports from untrusted networks
- **Null Session Restrictions**: Prevent anonymous access
- **Monitoring**: Log and alert on enumeration attempts

### For Penetration Testers:
- **Network Mapping**: Build comprehensive network diagrams
- **User Discovery**: Create target lists for password attacks
- **Share Assessment**: Identify sensitive data repositories
- **Domain Analysis**: Understand Active Directory structure

## Detection and Response

### Detection Methods:
- **Network Monitoring**: Watch for NetBIOS query patterns
- **Log Analysis**: Review Windows security logs
- **IDS Signatures**: Detect enumeration tool signatures
- **Behavioral Analysis**: Identify unusual NetBIOS activity

### Common Log Entries:
```
# Successful NetBIOS enumeration
Event ID 4624: Anonymous logon to IPC$ share
Event ID 5145: Network share object checked for access
Event ID 4648: Logon attempted using explicit credentials

# Failed enumeration attempts
Event ID 4625: Failed logon attempt
Event ID 5140: Network share object accessed
Event ID 5152: Windows Filtering Platform blocked connection
```

## Practical Applications

### Network Assessment:
- **Asset Discovery**: Identify Windows systems on network
- **Service Inventory**: Catalog available network services
- **Security Posture**: Assess information disclosure risks
- **Compliance Checking**: Verify security policy implementation

### Penetration Testing:
- **Initial Reconnaissance**: Gather target information
- **Attack Planning**: Identify potential attack vectors
- **Privilege Escalation**: Find high-value targets
- **Lateral Movement**: Discover network paths and resources

## CEH Exam Focus Points

- Understand NetBIOS ports (137, 138, 139) and their functions
- Know common NetBIOS suffix codes and their meanings
- Familiarize with key enumeration tools (nbtstat, enum4linux, rpcclient)
- Understand null session attacks and their implications
- Recognize the difference between NetBIOS and SMB protocols
- Know how to interpret NetBIOS enumeration output
- Understand security implications of NetBIOS information disclosure
