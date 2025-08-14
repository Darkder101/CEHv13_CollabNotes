# SMTP Enumeration

## Definition

SMTP (Simple Mail Transfer Protocol) Enumeration is the process of gathering information from mail servers to identify valid email addresses, user accounts, server configurations, and potential security vulnerabilities. SMTP operates primarily on ports 25 (standard), 465 (SMTPS), and 587 (submission). Attackers can exploit SMTP services to perform user enumeration, harvest email addresses, identify mail server software, and launch various email-based attacks.

## How SMTP Enumeration Works

### Basic Process:
1. **Port Scanning** identifies active SMTP services on standard ports
2. **Banner Grabbing** collects server identification and version information
3. **Command Testing** probes various SMTP commands for functionality
4. **User Enumeration** attempts to identify valid email addresses and accounts
5. **Relay Testing** checks for open relay configurations
6. **Vulnerability Assessment** identifies potential security weaknesses

### SMTP Protocol Structure:
- **Command Format**: Four-letter commands (HELO, MAIL, RCPT, DATA)
- **Response Codes**: Three-digit status codes with text descriptions
- **Session Flow**: Connection, authentication, message transfer, disconnection
- **Extensions**: ESMTP extensions for enhanced functionality

## SMTP Commands and Responses

| Command | Description | Usage |
|---------|-------------|-------|
| HELO/EHLO | Identify client to server | Session initiation |
| MAIL FROM | Specify sender address | Message envelope |
| RCPT TO | Specify recipient address | Delivery target |
| DATA | Begin message data transfer | Message content |
| VRFY | Verify user existence | User enumeration |
| EXPN | Expand mailing list | List enumeration |
| RSET | Reset session | Session management |
| QUIT | End session | Session termination |

## SMTP Response Codes

| Code Range | Category | Example |
|------------|----------|---------|
| 2xx | Success | 250 OK |
| 3xx | Intermediate | 354 Start mail input |
| 4xx | Temporary failure | 450 Mailbox unavailable |
| 5xx | Permanent failure | 550 User unknown |

## Tools and Commands

### Telnet SMTP Enumeration
```bash
# Connect to SMTP server
telnet target_ip 25

# Basic SMTP session
HELO attacker.com
VRFY root
VRFY admin
EXPN users
QUIT
```

### Nmap SMTP Enumeration
```bash
# SMTP service discovery
nmap -p 25,465,587 target_ip

# SMTP enumeration scripts
nmap -p 25 --script smtp-enum-users target_ip
nmap -p 25 --script smtp-commands target_ip
nmap -p 25 --script smtp-open-relay target_ip
nmap -p 25 --script smtp-vuln* target_ip

# Banner grabbing
nmap -sV -p 25 target_ip
```

### SMTP User Enumeration Tools
```bash
# smtp-user-enum (dedicated tool)
smtp-user-enum -M VRFY -U users.txt -t target_ip
smtp-user-enum -M EXPN -U users.txt -t target_ip
smtp-user-enum -M RCPT -U users.txt -t target_ip

# Custom enumeration with netcat
echo "VRFY root" | nc target_ip 25
echo "VRFY admin" | nc target_ip 25
```

### Metasploit SMTP Modules
```bash
# SMTP version detection
use auxiliary/scanner/smtp/smtp_version
set RHOSTS target_ip
run

# SMTP user enumeration
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS target_ip
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
run

# SMTP relay testing
use auxiliary/scanner/smtp/smtp_relay
set RHOSTS target_ip
run
```

## User Enumeration Techniques

### VRFY Command:
```
VRFY username
250 2.1.5 username <username@domain.com>  (valid user)
550 5.1.1 username... User unknown        (invalid user)
252 2.5.2 Cannot VRFY user                (disabled/restricted)
```

### EXPN Command:
```
EXPN mailinglist
250-2.1.5 user1@domain.com
250-2.1.5 user2@domain.com
250 2.1.5 user3@domain.com
```

### RCPT TO Method:
```
MAIL FROM: <attacker@test.com>
RCPT TO: <testuser@target.com>
250 2.1.5 OK                    (valid user)
550 5.1.1 User unknown          (invalid user)
```

## Banner Analysis

### Common SMTP Banners:
```
220 mail.example.com ESMTP Postfix (Ubuntu)
220 exchange.company.com Microsoft ESMTP MAIL Service ready
220 smtp.gmail.com ESMTP ready
220 mail.server.com ESMTP Sendmail 8.14.4
```

### Information Extraction:
- **Software Type**: Postfix, Sendmail, Exchange, qmail
- **Version Numbers**: Potential vulnerability identification
- **Operating System**: Ubuntu, Windows, CentOS
- **Hostname**: Internal network information
- **Organization**: Company or domain details

## SMTP Security Features

### Authentication Mechanisms:
- **PLAIN**: Base64-encoded username/password
- **LOGIN**: Similar to PLAIN with different encoding
- **CRAM-MD5**: Challenge-response authentication
- **DIGEST-MD5**: More secure digest authentication
- **OAUTH**: Modern token-based authentication

### Encryption Options:
- **STARTTLS**: Opportunistic encryption on port 25/587
- **SMTPS**: Implicit SSL/TLS on port 465
- **TLS Versions**: Protocol version support and configuration

## Enumeration Techniques

### Banner Grabbing:
```bash
# Basic banner collection
nc -nv target_ip 25
telnet target_ip 25

# SSL/TLS banner grabbing
openssl s_client -connect target_ip:465
openssl s_client -starttls smtp -connect target_ip:587
```

### Command Discovery:
```bash
# ESMTP capabilities
EHLO attacker.com

# Response analysis for supported features
250-mail.server.com
250-PIPELINING
250-SIZE 35882577
250-VRFY
250-ETRN
250-STARTTLS
250-AUTH PLAIN LOGIN
250-AUTH=PLAIN LOGIN
250 8BITMIME
```

### Open Relay Testing:
```bash
# External relay test
MAIL FROM: <external@attacker.com>
RCPT TO: <victim@external.com>
DATA
Subject: Relay Test
This is a relay test.
.

# Response codes indicate relay status
250 OK (potential open relay)
550 Relaying denied (properly configured)
```

## Security Vulnerabilities

### Common SMTP Vulnerabilities:
- **Open Mail Relay**: Allowing unauthorized email forwarding
- **User Enumeration**: VRFY/EXPN commands enabled
- **Information Disclosure**: Excessive banner information
- **Authentication Bypass**: Weak or missing authentication
- **Buffer Overflows**: Input validation vulnerabilities
- **Command Injection**: Improper input sanitization

### Known CVEs:
- **CVE-2020-28017**: Exim authentication bypass
- **CVE-2019-10149**: Exim remote code execution
- **CVE-2016-10009**: Postfix privilege escalation
- **CVE-2020-12783**: Exim out-of-bounds write
- **CVE-2021-38371**: Sendmail authentication bypass

## Attack Vectors

### Email Harvesting:
- **User Enumeration**: Building email address lists
- **Directory Enumeration**: Identifying organizational structure
- **Mailing List Discovery**: Finding group distribution lists
- **Contact Information**: Gathering personal details

### Phishing and Social Engineering:
- **Targeted Phishing**: Using enumerated addresses
- **Business Email Compromise**: Impersonating executives
- **Credential Harvesting**: Fake login pages
- **Malware Distribution**: Weaponized email attachments

### Server Exploitation:
- **Relay Abuse**: Using server for spam distribution
- **Buffer Overflow**: Exploiting parsing vulnerabilities
- **Authentication Attacks**: Brute force and credential stuffing
- **Denial of Service**: Resource exhaustion attacks

## Response Analysis

### Successful Enumeration:
```
Banner: 220 mail.company.com ESMTP Postfix (Ubuntu)
VRFY Results:
- admin@company.com: VALID
- support@company.com: VALID  
- info@company.com: VALID
- root@company.com: VALID

EXPN Results:
- administrators: admin@company.com, root@company.com
- support-team: support1@company.com, support2@company.com
```

### Restricted Server:
```
220 mail.secure.com ESMTP ready
VRFY root
252 2.5.2 Cannot VRFY user; try RCPT to attempt delivery
EXPN users
502 5.5.1 Command not implemented
Open Relay Test: 550 5.7.1 Relaying denied
```

### Vulnerable Configuration:
```
220 mail.vulnerable.com ESMTP Sendmail 8.12.8/8.12.8
VRFY: Enabled (users enumerable)
EXPN: Enabled (lists expandable)
Open Relay: Confirmed
Authentication: None required for relay
Encryption: Not supported
```

## System Response Behaviors

### Microsoft Exchange:
- **Banner**: Microsoft ESMTP MAIL Service ready
- **Features**: Autodiscover, OWA integration, Active Directory
- **Security**: Integrated Windows authentication, anti-spam
- **Vulnerabilities**: ProxyLogon, ProxyShell, Exchange-specific CVEs

### Postfix (Linux):
- **Banner**: ESMTP Postfix
- **Features**: Virtual domains, content filtering, rate limiting
- **Security**: SASL authentication, TLS encryption, access controls
- **Configuration**: Main.cf and master.cf files

### Sendmail (Unix):
- **Banner**: ESMTP Sendmail version
- **Features**: Flexible configuration, extensive ruleset system
- **Security**: Access database, authentication mechanisms
- **Legacy Issues**: Historical vulnerabilities, complex configuration

### Gmail/Google Workspace:
- **Banner**: ESMTP ready
- **Features**: Advanced spam filtering, OAuth authentication
- **Security**: Mandatory encryption, strict relay policies
- **Limitations**: Minimal enumeration capabilities

## Defensive Measures

### Server Hardening:
```
# Disable dangerous commands
VRFY disabled
EXPN disabled
ETRN restricted

# Rate limiting
Connection limits: 10 per IP
Message rate: 100/hour per sender

# Authentication requirements
Relay authentication: Required
SASL mechanisms: PLAIN, LOGIN over TLS only

# Banner modification
Custom banner: 220 Mail server ready (minimal info)
```

### Access Controls:
- **IP Restrictions**: Limit connections by source address
- **Authenticated Relay**: Require credentials for mail forwarding
- **Recipient Validation**: Verify addresses before accepting
- **Content Filtering**: Spam and malware detection
- **Rate Limiting**: Prevent abuse and DoS attacks

### Network Security:
```bash
# Firewall rules for SMTP
iptables -A INPUT -p tcp --dport 25 -m connlimit --connlimit-above 10 -j DROP
iptables -A INPUT -p tcp --dport 25 -m recent --set --name smtp
iptables -A INPUT -p tcp --dport 25 -m recent --update --seconds 60 --hitcount 20 --name smtp -j DROP
```

## Detection Methods

### Network Monitoring:
- **Connection Analysis**: Monitor SMTP connection patterns
- **Command Monitoring**: Log and analyze SMTP commands
- **Failed Authentication**: Track brute force attempts
- **Relay Attempts**: Detect unauthorized forwarding attempts

### Log Analysis:
```bash
# Postfix log analysis
grep "VRFY\|EXPN" /var/log/mail.log
grep "relay denied" /var/log/mail.log
grep "authentication failed" /var/log/mail.log

# Sendmail log analysis
grep "vrfy\|expn" /var/log/maillog
tail -f /var/log/maillog | grep -E "(reject|relay|auth)"
```

### Anomaly Detection:
- **Enumeration Patterns**: Rapid VRFY/EXPN attempts
- **Connection Spikes**: Unusual connection volumes
- **Geographic Anomalies**: Connections from unexpected locations
- **Time-based Analysis**: Off-hours reconnaissance activity

## Mitigation Strategies

### Configuration Hardening:
```
# Postfix hardening
disable_vrfy_command = yes
smtpd_banner = Mail server ready
smtpd_helo_required = yes
smtpd_relay_restrictions = permit_sasl_authenticated, reject

# Sendmail hardening
O PrivacyOptions=authwarnings,novrfy,noexpn,noetrn
O SmtpGreetingMessage=Mail server ready
O MaxDaemonChildren=20
```

### Authentication and Encryption:
- **Mandatory TLS**: Require encryption for all connections
- **Strong Authentication**: Implement robust SASL mechanisms
- **Certificate Validation**: Proper SSL/TLS certificate management
- **PFS Support**: Perfect Forward Secrecy for connections

### Monitoring and Alerting:
- **Real-time Monitoring**: SIEM integration for SMTP events
- **Automated Response**: Block suspicious IPs automatically
- **Threat Intelligence**: Integration with security feeds
- **Incident Response**: Procedures for SMTP-based attacks

## Practical Applications

### Penetration Testing:
- **Information Gathering**: Collect email addresses and user accounts
- **Service Fingerprinting**: Identify mail server software and versions
- **Vulnerability Assessment**: Test for known SMTP vulnerabilities
- **Social Engineering**: Prepare targeted phishing campaigns
- **Relay Testing**: Verify mail server security configuration

### Red Team Operations:
- **Reconnaissance**: Map organizational email structure
- **Credential Harvesting**: Identify high-value targets
- **Phishing Infrastructure**: Assess email security controls
- **Lateral Movement**: Use email for internal reconnaissance

### Security Assessment:
- **Configuration Review**: Evaluate SMTP server security settings
- **Compliance Testing**: Verify adherence to email security policies
- **Vulnerability Scanning**: Automated testing for SMTP issues
- **Risk Assessment**: Quantify email-related security risks

## Advanced Enumeration Techniques

### SSL/TLS Analysis:
```bash
# SSL certificate analysis
openssl s_client -connect target:465 -showcerts

# Cipher suite enumeration
nmap --script ssl-enum-ciphers -p 465 target_ip

# TLS version testing
openssl s_client -tls1_2 -connect target:587 -starttls smtp
```

### Timing-based Enumeration:
- **Response Time Analysis**: Different times for valid vs invalid users
- **Connection Patterns**: Behavioral analysis of server responses
- **Error Message Variations**: Subtle differences in error responses

### Automated Enumeration:
```bash
# Comprehensive user enumeration
for user in $(cat userlist.txt); do
  echo "VRFY $user" | nc target 25 | grep -E "(250|550)"
done

# Mailing list discovery
for list in $(cat lists.txt); do
  echo "EXPN $list" | nc target 25
done
```

## CEH Exam Focus Points

- Understand SMTP protocol basics and enumeration methodology
- Know key SMTP commands (VRFY, EXPN, RCPT TO) and their security implications
- Be familiar with common SMTP enumeration tools (nmap, telnet, smtp-user-enum)
- Recognize dangerous SMTP configurations (open relay, enabled VRFY/EXPN)
- Understand the relationship between SMTP enumeration and social engineering
- Know how to identify and exploit SMTP vulnerabilities
- Recognize proper SMTP hardening and security configurations
- Understand the role of SMTP in information gathering and reconnaissance phases
