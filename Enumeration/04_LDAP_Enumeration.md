# LDAP Enumeration

## Definition

LDAP (Lightweight Directory Access Protocol) Enumeration is a reconnaissance technique used to extract information from directory services by querying LDAP servers. LDAP operates on ports 389 (unencrypted) and 636 (LDAPS/encrypted). This enumeration method allows attackers to gather detailed information about domain structure, user accounts, groups, organizational units, and other directory objects, often through anonymous or null bind connections.

## How LDAP Enumeration Works

### Basic Process:
1. **Port Discovery** - Identify LDAP services on ports 389/636
2. **Connection Establishment** - Connect to LDAP server
3. **Authentication Testing** - Test anonymous/null bind access
4. **Base DN Discovery** - Identify directory base distinguished name
5. **Directory Tree Walking** - Enumerate directory structure
6. **Object Enumeration** - Extract user, group, and computer objects
7. **Attribute Extraction** - Gather detailed object attributes

### LDAP Components:
- **Directory Information Tree (DIT)**: Hierarchical directory structure
- **Distinguished Name (DN)**: Unique identifier for directory objects
- **Base DN**: Root of the directory tree
- **Organizational Units (OUs)**: Logical containers for objects
- **Attributes**: Properties of directory objects
- **Schema**: Defines object types and attributes

## LDAP Ports and Protocols

| Port | Protocol | Encryption | Description |
|------|----------|------------|-------------|
| 389  | TCP      | None       | Standard LDAP |
| 636  | TCP      | SSL/TLS    | LDAP over SSL (LDAPS) |
| 3268 | TCP      | None       | Global Catalog (AD) |
| 3269 | TCP      | SSL/TLS    | Global Catalog SSL (AD) |

## Common LDAP Attributes

| Attribute | Description | Example |
|-----------|-------------|---------|
| cn | Common Name | John Smith |
| sn | Surname | Smith |
| givenName | First Name | John |
| mail | Email Address | john.smith@company.com |
| telephoneNumber | Phone Number | +1-555-0123 |
| memberOf | Group Membership | CN=Admins,OU=Groups,DC=company,DC=com |
| objectClass | Object Type | user, group, organizationalUnit |
| distinguishedName | Full DN | CN=John Smith,OU=Users,DC=company,DC=com |
| samAccountName | Account Name | jsmith |
| userPrincipalName | User Principal | jsmith@company.com |

## Tools and Commands

### Ldapsearch (Linux)
```bash
# Anonymous bind enumeration
ldapsearch -x -h target_ip -p 389 -b ""

# Base DN discovery
ldapsearch -x -h target_ip -p 389 -b "" -s base

# User enumeration
ldapsearch -x -h target_ip -p 389 -b "dc=company,dc=com" "(objectclass=person)"

# Group enumeration
ldapsearch -x -h target_ip -p 389 -b "dc=company,dc=com" "(objectclass=group)"

# All objects enumeration
ldapsearch -x -h target_ip -p 389 -b "dc=company,dc=com" "(objectclass=*)"

# Specific attributes
ldapsearch -x -h target_ip -p 389 -b "dc=company,dc=com" "(objectclass=person)" cn mail

# Authentication with credentials
ldapsearch -x -h target_ip -p 389 -D "CN=user,DC=company,DC=com" -W -b "dc=company,dc=com"
```

### Ldapdomaindump
```bash
# Dump domain information
ldapdomaindump -u 'DOMAIN\username' -p password target_ip

# Anonymous dump
ldapdomaindump target_ip

# Specify output directory
ldapdomaindump -u 'DOMAIN\username' -p password -o /tmp/ldap target_ip

# JSON output format
ldapdomaindump -u 'DOMAIN\username' -p password --json target_ip
```

### Nmap LDAP Scripts
```bash
# LDAP root DSE enumeration
nmap -p 389 --script ldap-rootdse target_ip

# LDAP search enumeration
nmap -p 389 --script ldap-search --script-args 'ldap.base="dc=company,dc=com"' target_ip

# LDAP brute force
nmap -p 389 --script ldap-brute target_ip

# All LDAP scripts
nmap -p 389 --script ldap-* target_ip
```

### ADsearch (Windows)
```bash
# Search for users
adsearch "(&(objectClass=user)(objectCategory=person))"

# Search for groups
adsearch "(&(objectClass=group))"

# Search for computers
adsearch "(&(objectClass=computer))"

# Search with specific attributes
adsearch -b "dc=company,dc=com" "(&(objectClass=user))" cn mail samAccountName

# Search for privileged users
adsearch "(&(objectClass=user)(adminCount=1))"
```

### LDAPenum
```bash
# Basic enumeration
ldapenum target_ip

# Anonymous enumeration
ldapenum -a target_ip

# Authenticated enumeration
ldapenum -u username -p password target_ip

# Verbose output
ldapenum -v target_ip
```

### Python LDAP Scripts
```python
# Basic LDAP enumeration
import ldap

def enumerate_ldap(server):
    try:
        conn = ldap.initialize(f'ldap://{server}:389')
        conn.simple_bind_s('', '')  # Anonymous bind
        
        # Get base DN
        result = conn.search_s('', ldap.SCOPE_BASE, '(objectclass=*)')
        
        # Search for users
        users = conn.search_s('dc=company,dc=com', ldap.SCOPE_SUBTREE, 
                             '(objectclass=person)', ['cn', 'mail'])
        
        for user in users:
            print(user)
            
    except Exception as e:
        print(f"Error: {e}")
```

## Information Disclosure

### User Information:
- **Account Names**: Username and account identifiers
- **Personal Details**: Full names, email addresses, phone numbers
- **Group Memberships**: Security and distribution groups
- **Account Status**: Enabled/disabled accounts, locked accounts
- **Password Information**: Password policies and expiration dates
- **Logon Information**: Last logon times and logon scripts

### Group Information:
- **Security Groups**: Permissions and access control groups
- **Distribution Lists**: Email distribution groups
- **Group Membership**: Users belonging to specific groups
- **Nested Groups**: Groups that are members of other groups
- **Group Descriptions**: Purpose and function of groups

### Domain Information:
- **Domain Structure**: Organizational units and containers
- **Domain Controllers**: List of domain controllers
- **Domain Policies**: Password and account policies
- **Trusts**: Domain trust relationships
- **Schema Information**: Directory schema and extensions

### Computer Information:
- **Computer Accounts**: Domain-joined computers
- **Operating Systems**: OS versions and service packs
- **Service Accounts**: Accounts used by services
- **DNS Information**: Computer DNS names and addresses

## Advantages

- **Rich Information**: Comprehensive directory information
- **Standard Protocol**: LDAP widely implemented
- **Anonymous Access**: Often allows anonymous queries
- **Structured Data**: Well-organized hierarchical data
- **Multiple Interfaces**: Various tools and APIs available
- **Active Directory**: Deep integration with Windows domains

## Limitations

- **Authentication Required**: Modern systems require authentication
- **Access Controls**: Permissions may limit enumeration
- **Rate Limiting**: Servers may throttle excessive queries
- **Logging**: Queries are typically logged
- **Network Restrictions**: Firewalls may block LDAP traffic
- **SSL/TLS**: Encrypted connections complicate enumeration

## System Response Behaviors

### Active Directory:
- **Domain Controllers**: Full directory access when properly authenticated
- **Global Catalog**: Partial attribute sets for forest-wide searches
- **Read-Only DCs**: Limited write access but full read access
- **ADAM/AD LDS**: Application-specific directory partitions

### Other LDAP Implementations:
- **OpenLDAP**: Open source directory service
- **Apache Directory**: Java-based directory server
- **Oracle Directory**: Enterprise directory solution
- **IBM Tivoli**: Legacy enterprise directory

### Security Configurations:
- **Anonymous Bind**: Allows unauthenticated queries
- **Authenticated Access**: Requires valid credentials
- **SSL/TLS**: Encrypts communication channel
- **Access Controls**: Restricts access to specific objects/attributes

## Security Implications

### Attack Vectors:
- **User Enumeration**: Building target lists for attacks
- **Password Attacks**: Information for credential attacks
- **Privilege Escalation**: Identifying privileged accounts
- **Lateral Movement**: Understanding domain structure

### For Defenders:
- **Disable Anonymous Access**: Require authentication for queries
- **Access Controls**: Implement proper LDAP permissions
- **Monitoring**: Log and monitor LDAP queries
- **SSL/TLS**: Encrypt LDAP communications

### For Penetration Testers:
- **Domain Mapping**: Understanding organizational structure
- **Target Identification**: Finding high-value accounts
- **Attack Planning**: Using directory information for attacks
- **Privilege Analysis**: Identifying escalation paths

## Detection and Response

### Detection Methods:
- **Log Analysis**: Review LDAP server logs
- **Network Monitoring**: Monitor LDAP traffic patterns
- **Failed Binds**: Detect authentication attempts
- **Query Patterns**: Identify enumeration behavior

### Common Log Entries:
```
# Anonymous bind attempts
LDAP: Anonymous bind from 192.168.1.100
LDAP: Search request from anonymous connection

# Excessive queries
LDAP: High query volume from 192.168.1.100
LDAP: Enumeration pattern detected from single source

# Failed authentication
LDAP: Invalid credentials for CN=testuser,DC=company,DC=com
LDAP: Bind failure from 192.168.1.100
```

## Practical Applications

### Network Administration:
- **User Management**: Managing user accounts and attributes
- **Group Administration**: Managing security and distribution groups
- **Resource Access**: Controlling access to network resources
- **Directory Synchronization**: Syncing with other directories

### Security Assessment:
- **Account Auditing**: Reviewing user accounts and permissions
- **Group Analysis**: Analyzing group memberships and privileges
- **Policy Review**: Assessing directory security policies
- **Vulnerability Assessment**: Identifying security weaknesses

## CEH Exam Focus Points

- Understand LDAP ports (389, 636, 3268, 3269) and their purposes
- Know common LDAP enumeration tools (ldapsearch, nmap scripts)
- Understand LDAP directory structure (DN, CN, OU, DC)
- Recognize anonymous vs. authenticated LDAP access
- Know common LDAP attributes and object classes
- Understand Active Directory integration with LDAP
- Recognize security implications of LDAP information disclosure
- Know proper LDAP hardening techniques
