# Web Server Attacks Methodology

## Table of Contents
- [Web Server Attack Methodology Overview](#web-server-attack-methodology-overview)
- [1. Information Gathering](#1-information-gathering)
- [2. Web Server Footprinting](#2-web-server-footprinting)
- [3. Website Mirroring](#3-website-mirroring)
- [4. Vulnerability Scanning](#4-vulnerability-scanning)
- [5. Session Hijacking](#5-session-hijacking)
- [6. Web Server Password Hacking](#6-web-server-password-hacking)

---

## Web Server Attack Methodology Overview

Web servers are critical components of modern IT infrastructure, hosting websites and web applications that provide services to users worldwide. Understanding the methodology attackers use to compromise web servers is essential for ethical hackers and security professionals to identify vulnerabilities and implement appropriate countermeasures.

The web server attack methodology follows a systematic approach that includes information gathering, footprinting, vulnerability assessment, and exploitation. This methodology helps attackers identify weaknesses in web server configurations, software versions, and security implementations.

### Common Web Server Types
- **Apache HTTP Server** - Most widely used open-source web server
- **Microsoft IIS** - Windows-based web server with integrated .NET framework
- **Nginx** - High-performance web server and reverse proxy
- **Apache Tomcat** - Java-based application server
- **LiteSpeed** - Commercial web server optimized for performance

---

## 1. Information Gathering

Information gathering is the initial phase where attackers collect publicly available information about the target web server and organization.

### 1.1 Whois Lookup

Whois databases contain registration information about domain names, IP addresses, and autonomous systems.

**Key Information Retrieved:**
- Domain registration details
- Registrant contact information
- Name servers
- Registration and expiration dates
- Administrative and technical contacts

**Tools for Whois Lookup:**
- `whois` command-line tool
- Online Whois databases
- DomainTools
- Whois.net

**Example Command:**
```bash
whois example.com
```

**Information Analysis:**
- Identify domain registrar and hosting provider
- Discover associated email addresses and phone numbers
- Determine domain expiration dates
- Find additional domains registered by the same entity

### 1.2 Using robots.txt

The robots.txt file provides valuable information about the website structure and hidden directories.

**Purpose of robots.txt:**
- Instructs web crawlers which pages to index
- Contains disallow directives for sensitive areas
- May reveal administrative interfaces and backup files

**Common Findings in robots.txt:**
- Administrative panels (`/admin`, `/administrator`)
- Database backup locations (`/backup`, `/db`)
- Configuration files (`/config`, `/includes`)
- Development directories (`/dev`, `/test`)

**Access Method:**
```
http://target-website.com/robots.txt
```

**Analysis Techniques:**
- Review disallowed directories for sensitive information
- Check for sitemap references
- Look for patterns indicating content management systems
- Identify potential attack vectors through exposed paths

---

## 2. Web Server Footprinting

Web server footprinting involves actively probing the target server to gather technical information about its configuration, software versions, and available services.

### 2.1 Netcat

Netcat is a versatile networking tool used for port scanning, banner grabbing, and basic service enumeration.

**Basic Banner Grabbing:**
```bash
nc target-ip 80
GET / HTTP/1.1
Host: target-website.com

```

**Information Gathered:**
- Web server software and version
- Operating system details
- Server response headers
- Available HTTP methods

**Advanced Techniques:**
- Test for specific HTTP methods (OPTIONS, TRACE)
- Analyze response timing for server identification
- Check for custom headers revealing internal architecture

### 2.2 Telnet

Telnet provides similar functionality to netcat for manual HTTP requests and banner grabbing.

**Basic HTTP Request:**
```bash
telnet target-ip 80
GET / HTTP/1.1
Host: target-website.com

```

**SSL/TLS Testing:**
```bash
telnet target-ip 443
```

**Common Applications:**
- Manual HTTP header analysis
- Testing for HTTP method availability
- Analyzing server response patterns
- Identifying load balancers and proxy servers

### 2.3 Httprecon

Httprecon is a specialized web server fingerprinting tool that uses advanced techniques to identify server software.

**Key Features:**
- Advanced fingerprinting algorithms
- Database of server signatures
- Detailed reporting capabilities
- Support for various HTTP methods

**Usage Scenarios:**
- Accurate server identification when basic methods fail
- Detailed analysis of server behavior patterns
- Identification of server modifications and customizations

### 2.4 Uniscan

Uniscan is a comprehensive web vulnerability scanner that combines multiple scanning techniques.

**Core Capabilities:**
- Directory and file discovery
- Vulnerability detection
- Web server fingerprinting
- Remote file inclusion testing

**Scan Types:**
- Dynamic scanning for vulnerabilities
- Static file discovery
- Remote and local file inclusion testing
- SQL injection detection

### 2.5 Netcraft

Netcraft provides extensive information about web servers and hosting infrastructure.

**Information Available:**
- Web server technology stack
- Hosting provider details
- SSL certificate information
- Site uptime statistics
- Technology change history

**Research Capabilities:**
- Historical server information
- Subdomain discovery
- IP address ranges
- Related domain identification

### 2.6 ID Serve

ID Serve specializes in HTTP server identification and fingerprinting.

**Identification Methods:**
- HTTP header analysis
- Response pattern matching
- Error page fingerprinting
- Server behavior analysis

**Output Information:**
- Exact server software and version
- Module information
- Configuration details
- Operating system identification

### 2.7 Nmap

Nmap provides comprehensive port scanning and service enumeration capabilities.

**Web Server Scanning:**
```bash
nmap -sV -p80,443 target-ip
nmap --script http-enum target-ip
nmap --script http-methods target-ip
```

**HTTP-Specific Scripts:**
- `http-enum` - Enumerates directories and files
- `http-methods` - Tests for available HTTP methods
- `http-headers` - Analyzes HTTP headers
- `http-title` - Retrieves page titles

**Advanced Scanning:**
```bash
nmap --script "http-*" target-ip
nmap -sV --script http-enum,http-headers,http-methods target-ip
```

### 2.8 Ghost Eye

Ghost Eye is an information gathering tool focused on comprehensive target analysis.

**Data Collection:**
- WHOIS information
- DNS records
- Subdomain enumeration
- Port scanning results

**Reporting Features:**
- Consolidated information display
- Export capabilities
- Visual representation of findings

### 2.9 Skipfish

Skipfish is an active web application security reconnaissance tool.

**Scanning Capabilities:**
- Comprehensive site crawling
- Vulnerability identification
- Content discovery
- Security issue reporting

**Key Features:**
- High-speed scanning
- Minimal false positives
- Detailed security reports
- Automated vulnerability categorization

### 2.10 IIS Information Gathering using Shodan

Shodan provides extensive information about Internet-connected devices, including IIS servers.

**Search Queries for IIS:**
```
Server: Microsoft-IIS
"Microsoft-IIS/10.0"
port:80,443 iis
```

**Information Available:**
- Server versions and configurations
- Geographic distribution
- Associated vulnerabilities
- SSL certificate details

**Advanced Searches:**
- Version-specific queries
- Location-based filtering
- Vulnerability-focused searches
- Service combination queries

### 2.11 Abusing Apache mod_userdir to Enumerate User Accounts

The mod_userdir module allows users to serve content from their home directories.

**Enumeration Technique:**
```bash
curl http://target-server/~username/
```

**Common Usernames to Test:**
- admin, administrator
- root, user
- www-data, apache
- Common first names

**Information Gathered:**
- Valid user accounts
- User directory contents
- Personal web pages
- Configuration files

### 2.12 Using Nmap for Advanced Web Server Enumeration

Nmap provides specialized scripts for detailed web server analysis.

**Comprehensive Web Server Scan:**
```bash
nmap -sS -sV -O --script "http-*" -p80,443,8080,8443 target-ip
```

**Specific Script Categories:**
```bash
# Authentication testing
nmap --script http-auth target-ip

# Configuration issues
nmap --script http-config-backup target-ip

# Directory traversal
nmap --script http-passwd target-ip
```

### 2.13 Using Default Credentials of Web Servers

Many web servers and applications ship with default credentials that are often unchanged.

**Common Default Credentials:**

**Apache/Tomcat:**
- admin/admin
- tomcat/tomcat
- admin/tomcat

**IIS/ASP.NET:**
- administrator/(blank)
- admin/admin
- sa/(blank)

**Generic Web Applications:**
- admin/password
- root/root
- guest/guest

**Testing Methods:**
- Manual login attempts
- Automated credential testing tools
- Configuration file analysis

### 2.14 Directory Brute-forcing

Directory brute-forcing discovers hidden directories and files on web servers.

**Popular Tools:**

**DirBuster:**
- GUI-based directory brute-forcing
- Customizable wordlists
- Threading support

**Gobuster:**
```bash
gobuster dir -u http://target-ip -w /path/to/wordlist.txt
gobuster dir -u http://target-ip -w /usr/share/wordlists/dirb/common.txt
```

**Dirbuster/OWASP ZAP:**
- Integrated scanning capabilities
- Advanced filtering options
- Custom wordlist support

**Common Directories to Test:**
- /admin, /administrator
- /backup, /old
- /config, /configuration
- /test, /dev
- /uploads, /files

---

## 3. Website Mirroring

Website mirroring creates local copies of target websites for offline analysis and vulnerability assessment.

### Purpose of Website Mirroring
- Offline analysis and testing
- Content structure examination
- Source code analysis
- Link and form discovery

### Tools for Website Mirroring

**HTTrack:**
```bash
httrack http://target-website.com -O /local/directory
```

**Wget:**
```bash
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent http://target-website.com
```

**Curl with Scripting:**
```bash
curl -s http://target-website.com | grep -oE 'href="[^"]*"' | cut -d'"' -f2
```

### Analysis of Mirrored Content

**Source Code Review:**
- Hidden form fields
- JavaScript functions
- Comment sections with sensitive information
- Hard-coded credentials or API keys

**Directory Structure Analysis:**
- Administrative interfaces
- Database connection files
- Configuration files
- Backup directories

**Link Analysis:**
- Internal application structure
- External dependencies
- API endpoints
- Hidden functionality

---

## 4. Vulnerability Scanning

Vulnerability scanning identifies security weaknesses in web servers and applications through automated testing.

### Types of Vulnerability Scans

**Network-Level Scanning:**
- Port scanning and service enumeration
- Operating system fingerprinting
- Service version detection
- Protocol-specific testing

**Application-Level Scanning:**
- Web application vulnerability assessment
- Input validation testing
- Authentication mechanism analysis
- Session management evaluation

### Popular Vulnerability Scanners

**OpenVAS:**
- Comprehensive vulnerability assessment
- Extensive vulnerability database
- Detailed reporting capabilities
- Custom scan configuration

**Nessus:**
- Commercial vulnerability scanner
- Regular vulnerability feed updates
- Policy-based scanning
- Compliance checking

**Nikto:**
```bash
nikto -h http://target-website.com
nikto -h target-ip -p 80,443
```

**Common Vulnerabilities Detected:**
- Outdated software versions
- Default configurations
- Insecure HTTP methods
- Directory traversal vulnerabilities
- Cross-site scripting (XSS)
- SQL injection vulnerabilities

### Manual Vulnerability Testing

**HTTP Method Testing:**
```bash
curl -X OPTIONS http://target-website.com
curl -X TRACE http://target-website.com
curl -X PUT http://target-website.com/test.txt -d "test data"
```

**Directory Traversal Testing:**
```
http://target-website.com/../../../../etc/passwd
http://target-website.com/..\..\windows\system32\drivers\etc\hosts
```

**Input Validation Testing:**
- SQL injection attempts
- Cross-site scripting payloads
- Command injection testing
- File upload validation

---

## 5. Session Hijacking

Session hijacking involves stealing or manipulating user sessions to gain unauthorized access to web applications.

### Types of Session Attacks

**Session ID Prediction:**
- Analysis of session ID generation patterns
- Weak random number generator exploitation
- Sequential session ID identification

**Session Fixation:**
- Forcing users to use predetermined session IDs
- Exploiting applications that accept session IDs in URLs
- Cross-site request forgery integration

**Session Sidejacking:**
- Intercepting session cookies over unencrypted connections
- WiFi network sniffing
- Man-in-the-middle attacks

### Tools for Session Analysis

**Burp Suite:**
- Session token analysis
- Sequencer tool for randomness testing
- Proxy for session manipulation
- Automated session testing

**OWASP ZAP:**
- Session management testing
- Automated security scanning
- Session token strength analysis

**Wireshark:**
- Network traffic capture and analysis
- Session cookie interception
- Protocol-level session analysis

### Session Security Testing

**Cookie Analysis:**
- Secure flag verification
- HttpOnly flag checking
- SameSite attribute analysis
- Domain and path scope evaluation

**Session Timeout Testing:**
- Idle timeout verification
- Absolute timeout checking
- Session renewal mechanisms

**Session Invalidation:**
- Logout functionality testing
- Session destruction verification
- Cross-device session management

---

## 6. Web Server Password Hacking

Password attacks against web servers target authentication mechanisms through various techniques.

### Types of Password Attacks

**Brute Force Attacks:**
- Systematic password guessing
- Dictionary-based attacks
- Hybrid attack methods
- Rule-based password generation

**Credential Stuffing:**
- Using leaked credential databases
- Automated login attempts
- Account validation techniques

### Tools for Password Attacks

**Hydra:**
```bash
hydra -l admin -P passwords.txt http-get://target-ip/admin
hydra -L users.txt -P passwords.txt target-ip http-post-form "/login:username=^USER^&password=^PASS^:Invalid"
```

**Medusa:**
```bash
medusa -h target-ip -u admin -P passwords.txt -M http
```

**Burp Suite Intruder:**
- Customizable payload generation
- Position-based attack configuration
- Response analysis and filtering
- Rate limiting and throttling

### Common Attack Vectors

**HTTP Basic Authentication:**
```bash
hydra -l username -P wordlist.txt target-ip http-get /protected-area
```

**Form-Based Authentication:**
- POST parameter identification
- Response pattern analysis
- Session handling during attacks
- CSRF token management

**Windows Authentication:**
- NTLM authentication attacks
- Kerberos ticket manipulation
- Domain credential testing

### Password Security Testing

**Password Policy Analysis:**
- Minimum length requirements
- Complexity requirements
- Password history checking
- Account lockout policies

**Authentication Bypass Testing:**
- SQL injection in login forms
- Authentication logic flaws
- Default credential testing
- Multi-factor authentication bypass
---

## Key Takeaways for CEH v13 Exam

1. **Information Gathering** - Master WHOIS lookups and robots.txt analysis
2. **Footprinting Tools** - Understand Netcat, Nmap, and specialized web server identification tools
3. **Vulnerability Assessment** - Know how to use Nikto, OpenVAS, and manual testing techniques
4. **Session Security** - Understand session hijacking methods and countermeasures
5. **Password Attacks** - Be familiar with Hydra, Medusa, and authentication bypass techniques
6. **Methodology** - Follow the systematic approach from information gathering to exploitation
