# More Enumeration Techniques

## Definition

More Enumeration Techniques encompasses advanced and specialized methods for gathering information from various network services, protocols, and applications beyond standard enumeration approaches. This includes enumeration of database services, web applications, LDAP directories, SNMP devices, NetBIOS/SMB shares, and other specialized services. These techniques provide comprehensive reconnaissance capabilities for identifying vulnerabilities, misconfigurations, and potential attack vectors across diverse network infrastructures.

## Database Enumeration

### MySQL Enumeration:
```bash
# MySQL service detection
nmap -p 3306 --script mysql-info target_ip

# MySQL user enumeration
nmap -p 3306 --script mysql-users --script-args mysqluser=root target_ip

# MySQL database enumeration
nmap -p 3306 --script mysql-databases --script-args mysqluser=root target_ip

# MySQL empty password check
nmap -p 3306 --script mysql-empty-password target_ip
```

### MSSQL Enumeration:
```bash
# MSSQL service detection
nmap -p 1433 --script ms-sql-info target_ip

# MSSQL empty password
nmap -p 1433 --script ms-sql-empty-password target_ip

# MSSQL brute force
nmap -p 1433 --script ms-sql-brute target_ip

# MSSQL configuration
nmap -p 1433 --script ms-sql-config target_ip
```

### Oracle Enumeration:
```bash
# Oracle TNS listener
nmap -p 1521 --script oracle-tns-version target_ip

# Oracle SID enumeration
nmap -p 1521 --script oracle-sid-brute target_ip

# Oracle user enumeration
oscanner -s target_ip -P 1521

# Oracle version detection
tnscmd10g version -h target_ip -p 1521
```

### PostgreSQL Enumeration:
```bash
# PostgreSQL service detection
nmap -p 5432 --script pgsql-brute target_ip

# PostgreSQL database enumeration
psql -h target_ip -U postgres -l

# PostgreSQL user enumeration
psql -h target_ip -U postgres -c "\du"
```

## SMB Enumeration

### SMB Share Enumeration:
```bash
# SMB share discovery
smbmap -H target_ip

# SMB share access testing
smbmap -H target_ip -u null -p ""

# Recursive share enumeration
smbmap -H target_ip -R

# SMB file download
smbmap -H target_ip --download 'share\file.txt'
```

### Advanced SMB Enumeration:
```bash
# SMB version detection
smbver target_ip

# SMB user enumeration
enum4linux target_ip

# SMB policy enumeration
enum4linux -P target_ip

# SMB group enumeration
enum4linux -G target_ip
```

## Web Application Enumeration

### Directory and File Discovery:
```bash
# Directory brute force
dirb http://target.com /usr/share/wordlists/dirb/common.txt

# Gobuster directory enumeration
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Recursive directory search
dirbuster -u http://target.com -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# File extension discovery
gobuster dir -u http://target.com -w wordlist.txt -x php,asp,aspx,jsp
```

### Web Technology Identification:
```bash
# Technology stack identification
whatweb target.com

# HTTP header analysis
curl -I http://target.com

# Wappalyzer command line
wappalyzer http://target.com

# Builtwith analysis
builtwith target.com
```

### CMS-Specific Enumeration:
```bash
# WordPress enumeration
wpscan --url http://target.com --enumerate u,t,p

# Joomla enumeration
joomscan -u http://target.com

# Drupal enumeration
droopescan scan drupal -u http://target.com

# Magento enumeration
magescan scan:all http://target.com
```

## FTP Enumeration

### FTP Service Enumeration:
```bash
# FTP banner grabbing
nmap -sV -p 21 target_ip

# FTP anonymous access
nmap -p 21 --script ftp-anon target_ip

# FTP bounce attack test
nmap -p 21 --script ftp-bounce target_ip

# FTP brute force
nmap -p 21 --script ftp-brute target_ip
```

### FTP Manual Testing:
```bash
# Anonymous FTP access
ftp target_ip
# Username: anonymous
# Password: anonymous@domain.com

# FTP directory listing
ls -la
dir

# FTP file operations
get filename
put localfile
mget *.txt
```

## SSH Enumeration

### SSH Service Analysis:
```bash
# SSH version detection
nmap -sV -p 22 target_ip

# SSH algorithm enumeration
nmap -p 22 --script ssh2-enum-algos target_ip

# SSH host key extraction
nmap -p 22 --script ssh-hostkey target_ip

# SSH authentication methods
nmap -p 22 --script ssh-auth-methods target_ip
```

### SSH Security Testing:
```bash
# SSH brute force
nmap -p 22 --script ssh-brute target_ip

# SSH weak key detection
ssh-keyscan target_ip

# SSH version vulnerabilities
searchsploit ssh version
```

## RDP Enumeration

### RDP Service Detection:
```bash
# RDP service enumeration
nmap -p 3389 --script rdp-enum-encryption target_ip

# RDP user enumeration
nmap -p 3389 --script rdp-vuln-ms12-020 target_ip

# RDP screenshot
nmap -p 3389 --script rdp-screenshot target_ip
```

### RDP Security Assessment:
```bash
# RDP brute force
ncrack -vv --user administrator -P passwords.txt rdp://target_ip

# RDP connection testing
rdesktop target_ip

# RDP certificate analysis
openssl s_client -connect target_ip:3389
```

## VPN Service Enumeration

### IPSec VPN Enumeration:
```bash
# IPSec VPN discovery
ike-scan target_ip

# IPSec aggressive mode
ike-scan -A target_ip

# IPSec PSK cracking
psk-crack -d wordlist.txt capture.pcap
```

### SSL VPN Enumeration:
```bash
# SSL VPN detection
nmap -p 443,4443 --script ssl-cert target_ip

# SSL VPN fingerprinting
whatweb https://target_ip:4443/

# SSL VPN vulnerability scanning
nmap -p 443 --script ssl-enum-ciphers target_ip
```

## Advanced Enumeration Techniques

### Port Knocking Detection:
```bash
# Port knock sequence detection
knock target_ip 7000 8000 9000

# Port knock automation
for i in {1000..9000}; do
  nc -z -w1 target_ip $i && echo "Port $i open"
done
```

### Service Version Fingerprinting:
```bash
# Comprehensive service detection
nmap -sV -sC --version-all target_ip

# Aggressive fingerprinting
nmap -A -T4 target_ip

# Custom service probes
nmap --script-args http.useragent="CustomAgent" target_ip
```

### Stealth Enumeration:
```bash
# Slow scan to avoid detection
nmap -sS -T2 -f target_ip

# Random scan order
nmap --randomize-hosts -iL targets.txt

# Decoy scanning
nmap -D decoy1,decoy2,ME target_ip
```

## Vulnerability-Specific Enumeration

### Eternal Blue (MS17-010):
```bash
# EternalBlue detection
nmap -p 445 --script smb-vuln-ms17-010 target_ip

# SMB protocol enumeration
smbver target_ip

# SMB vulnerability comprehensive scan
nmap -p 445 --script smb-vuln* target_ip
```

### Shellshock (CVE-2014-6271):
```bash
# Shellshock detection
nmap -p 80 --script http-shellshock --script-args uri=/cgi-bin/test.cgi target_ip

# Manual shellshock testing
curl -H "User-Agent: () { :; }; echo; echo vulnerable" http://target/cgi-bin/test.sh
```

### Heartbleed (CVE-2014-0160):
```bash
# Heartbleed detection
nmap -p 443 --script ssl-heartbleed target_ip

# Manual heartbleed testing
sslscan --heartbleed target_ip:443
```

## Enumeration Automation

### Custom Enumeration Scripts:
```bash
#!/bin/bash
# Comprehensive enumeration script
target=$1

echo "Starting enumeration of $target"

# Network discovery
nmap -sn $target/24 > hosts.txt

# Port scanning
nmap -sS -O $target > portscan.txt

# Service enumeration
nmap -sV -sC $target > services.txt

# Vulnerability scanning
nmap --script vuln $target > vulns.txt

echo "Enumeration complete"
```

### Multi-Protocol Enumeration:
```bash
# Automated service enumeration
autorecon target_ip

# Comprehensive enumeration
nmapAutomator target_ip All

# Custom enumeration pipeline
enum4linux target_ip && smbmap -H target_ip && snmpwalk -v2c -c public target_ip
```

## Detection and Mitigation

### Enumeration Detection:
- **Network Monitoring**: Unusual connection patterns and port scans
- **Log Analysis**: Failed authentication attempts and service probes
- **IDS/IPS Signatures**: Known enumeration tool signatures
- **Behavioral Analysis**: Automated scanning patterns

### Mitigation Strategies:
- **Service Hardening**: Disable unnecessary services and features
- **Access Controls**: Implement proper authentication and authorization
- **Network Segmentation**: Isolate critical services
- **Rate Limiting**: Prevent brute force and scanning attempts
- **Monitoring and Alerting**: Real-time detection and response

## Practical Applications

### Penetration Testing:
- **Asset Discovery**: Comprehensive service and application mapping
- **Vulnerability Assessment**: Identify security weaknesses across services
- **Attack Vector Analysis**: Map potential entry points and escalation paths
- **Security Posture Evaluation**: Assess overall security configuration

### Red Team Operations:
- **Intelligence Gathering**: Deep reconnaissance of target infrastructure
- **Attack Planning**: Prioritize targets based on enumerated services
- **Persistence Planning**: Identify services for backdoor placement
- **Lateral Movement**: Map internal services and trust relationships

### Blue Team Defense:
- **Asset Inventory**: Maintain comprehensive service catalogs
- **Security Monitoring**: Implement enumeration detection capabilities
- **Vulnerability Management**: Regular scanning and remediation
- **Incident Response**: Investigate and respond to enumeration attempts

## CEH Exam Focus Points

- Understand enumeration concepts across multiple protocols and services
- Know specific enumeration tools for different services (LDAP, SNMP, databases)
- Be familiar with NetBIOS/SMB enumeration techniques and tools
- Recognize web application enumeration methodologies and tools
- Understand database-specific enumeration approaches
- Know how to identify and exploit service misconfigurations
- Recognize advanced enumeration techniques and automation approaches
- Understand the relationship between enumeration and vulnerability assessment
