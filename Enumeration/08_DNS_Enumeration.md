# DNS Enumeration

## Definition

DNS (Domain Name System) Enumeration is the process of gathering information about domain names, subdomains, IP addresses, and DNS infrastructure to map network topology and identify potential attack vectors. DNS operates primarily on port 53 (UDP/TCP) and serves as a critical information source for reconnaissance. Attackers can exploit DNS services to discover network architecture, identify services, perform zone transfers, and gather intelligence for further attacks.

## How DNS Enumeration Works

### Basic Process:
1. **Domain Discovery** identifies target domains and subdomains
2. **Record Type Queries** extract various DNS record types (A, AAAA, MX, NS, etc.)
3. **Zone Transfer Attempts** try to obtain complete zone databases
4. **Reverse DNS Lookups** map IP addresses to hostnames
5. **DNS Server Enumeration** identifies authoritative and recursive servers
6. **Cache Poisoning Tests** assess DNS security vulnerabilities

### DNS Record Types:
- **A Record**: Maps domain to IPv4 address
- **AAAA Record**: Maps domain to IPv6 address
- **MX Record**: Mail exchange servers
- **NS Record**: Name servers for domain
- **CNAME Record**: Canonical name aliases
- **TXT Record**: Text information (SPF, DKIM, etc.)
- **PTR Record**: Reverse DNS mapping
- **SOA Record**: Start of authority information

## DNS Query Types and Classes

| Record Type | Purpose | Information Revealed |
|-------------|---------|---------------------|
| A | IPv4 address resolution | Host IP addresses |
| AAAA | IPv6 address resolution | IPv6 addresses |
| MX | Mail exchange | Mail server hierarchy |
| NS | Name servers | DNS infrastructure |
| CNAME | Canonical names | Domain aliases |
| TXT | Text records | SPF, DKIM, policies |
| PTR | Reverse lookup | Hostname from IP |
| SOA | Zone authority | Zone configuration |
| SRV | Service records | Service locations |

## Tools and Commands

### Basic DNS Queries
```bash
# A record lookup
nslookup target.com
dig target.com A

# Multiple record types
dig target.com ANY
dig target.com MX
dig target.com NS
dig target.com TXT

# Reverse DNS lookup
nslookup 192.168.1.1
dig -x 192.168.1.1
```

### Advanced DNS Enumeration
```bash
# Zone transfer attempt
dig @ns1.target.com target.com AXFR
host -l target.com ns1.target.com

# Subdomain enumeration
dnsrecon -d target.com -t std
dnsrecon -d target.com -t brt -D subdomains.txt

# DNS bruteforce
dnsmap target.com
fierce -dns target.com

# Cache snooping
dig @dns-server target.com +norecurse
```

### Nmap DNS Enumeration
```bash
# DNS service discovery
nmap -sU -p 53 target_ip

# DNS enumeration scripts
nmap -p 53 --script dns-zone-transfer target_ip
nmap -p 53 --script dns-recursion target_ip
nmap -p 53 --script dns-cache-snoop target_ip
nmap -p 53 --script dns-brute target.com
```

### Specialized DNS Tools
```bash
# DNSEnum comprehensive enumeration
dnsenum target.com

# Sublist3r subdomain discovery
sublist3r -d target.com

# Amass comprehensive enumeration
amass enum -d target.com

# DNSRecon with different techniques
dnsrecon -d target.com -t axfr
dnsrecon -d target.com -t rvl -r 192.168.1.0/24
```

## DNS Enumeration Techniques

### Zone Transfer Enumeration:
```bash
# Identify name servers
dig target.com NS

# Attempt zone transfer from each NS
dig @ns1.target.com target.com AXFR
dig @ns2.target.com target.com AXFR

# TCP zone transfer
dig @ns1.target.com target.com AXFR +tcp
```

### Subdomain Discovery:
```bash
# Dictionary-based enumeration
for sub in $(cat subdomains.txt); do
  dig ${sub}.target.com | grep -v "NXDOMAIN"
done

# Reverse IP lookup for subdomains
dnsrecon -d target.com -t rvl -r 192.168.1.0/24

# Certificate transparency logs
curl -s "https://crt.sh/?q=%.target.com&output=json"
```

### DNS Cache Analysis:
```bash
# Cache snooping for popular domains
dig @target_dns google.com +norecurse
dig @target_dns facebook.com +norecurse

# Cache poisoning test
dig @target_dns nonexistent.target.com
```

## DNS Security Features and Vulnerabilities

### DNSSEC (DNS Security Extensions):
- **Digital Signatures**: Cryptographic validation of DNS responses
- **Chain of Trust**: Hierarchical validation from root to leaf
- **Key Management**: KSK (Key Signing Key) and ZSK (Zone Signing Key)
- **Validation States**: Secure, insecure, bogus, indeterminate

### Common DNS Vulnerabilities:
- **Zone Transfer**: Unauthorized zone database access
- **Cache Poisoning**: DNS response manipulation
- **DNS Tunneling**: Data exfiltration through DNS queries
- **DNS Amplification**: DDoS attack vector
- **Subdomain Takeover**: Claiming abandoned subdomains
- **DNS Rebinding**: Bypassing same-origin policy

### Known CVEs:
- **CVE-2020-1350**: Windows DNS Server RCE (SIGRed)
- **CVE-2017-15105**: Unbound DNS validation bypass
- **CVE-2020-25705**: Unbound assertion failure
- **CVE-2021-25220**: BIND response policy zone bypass

## Information Gathering Techniques

### Domain Intelligence:
```bash
# WHOIS information
whois target.com

# DNS history
dig target.com +trace
dig target.com +noall +answer +additional

# Public DNS databases
# Certificate transparency
# Passive DNS databases
```

### Infrastructure Mapping:
```bash
# Mail server enumeration
dig target.com MX

# Name server identification
dig target.com NS

# Service discovery
dig _http._tcp.target.com SRV
dig _ftp._tcp.target.com SRV
```

### IP Address Resolution:
```bash
# IPv4 addresses
dig target.com A

# IPv6 addresses
dig target.com AAAA

# IP range identification
whois 192.168.1.1
```

## Response Analysis

### Successful Zone Transfer:
```
; target.com zone transfer
target.com.        IN    SOA   ns1.target.com. admin.target.com.
target.com.        IN    NS    ns1.target.com.
target.com.        IN    NS    ns2.target.com.
target.com.        IN    A     192.168.1.10
www.target.com.    IN    A     192.168.1.11
mail.target.com.   IN    A     192.168.1.12
ftp.target.com.    IN    A     192.168.1.13
admin.target.com.  IN    A     192.168.1.14
```

### Restricted Zone Transfer:
```
; Transfer failed.
; <<>> DiG 9.16.1 <<>> @ns1.target.com target.com AXFR
;; communications error to ns1.target.com: connection refused
;; Transfer failed.
```

### Subdomain Enumeration Results:
```
Found subdomains:
www.target.com      192.168.1.11
mail.target.com     192.168.1.12
ftp.target.com      192.168.1.13
admin.target.com    192.168.1.14
test.target.com     192.168.1.15
dev.target.com      192.168.1.16
```

## DNS Server Types and Behaviors

### Authoritative Servers:
- **Primary (Master)**: Contains original zone data
- **Secondary (Slave)**: Synchronizes from primary
- **Hidden Master**: Not publicly listed but serves secondaries
- **Zone Configuration**: Controls transfer permissions

### Recursive Servers:
- **Public Resolvers**: Google (8.8.8.8), Cloudflare (1.1.1.1)
- **ISP Resolvers**: Provider-specific DNS servers
- **Local Resolvers**: Corporate or organizational servers
- **Forwarding Servers**: Relay queries to upstream servers

### DNS Server Software:
- **BIND**: Berkeley Internet Name Domain (most common)
- **Microsoft DNS**: Windows Server DNS service
- **PowerDNS**: High-performance authoritative server
- **Unbound**: Validating recursive resolver
- **dnsmasq**: Lightweight DHCP/DNS server

## Attack Vectors

### Information Disclosure:
- **Zone Transfer**: Complete domain database access
- **Subdomain Discovery**: Hidden services and applications
- **Infrastructure Mapping**: Network topology revelation
- **Email Harvesting**: MX record analysis for targets

### DNS-based Attacks:
- **Cache Poisoning**: Malicious DNS response injection
- **DNS Tunneling**: Covert communication channels
- **Subdomain Takeover**: Claiming abandoned services
- **DNS Amplification**: DDoS attack amplification
- **Pharming**: Domain hijacking for redirection

### Follow-up Attacks:
- **Service Enumeration**: Port scanning discovered hosts
- **Vulnerability Scanning**: Testing identified services
- **Social Engineering**: Using gathered domain information
- **Credential Attacks**: Targeting discovered services

## Defensive Measures

### Zone Transfer Protection:
```
# BIND configuration example
zone "target.com" {
    type master;
    file "/var/named/target.com.zone";
    allow-transfer { 192.168.1.2; 192.168.1.3; };
    notify yes;
    also-notify { 192.168.1.2; 192.168.1.3; };
};
```

### DNS Security Implementation:
- **DNSSEC Deployment**: Enable cryptographic validation
- **Access Controls**: Restrict zone transfers and queries
- **Rate Limiting**: Prevent abuse and amplification
- **Monitoring**: Log and analyze DNS queries
- **Response Policy Zones**: Block malicious domains

### Network Security:
```bash
# Firewall rules for DNS
iptables -A INPUT -p udp --dport 53 -m recent --set --name dns
iptables -A INPUT -p udp --dport 53 -m recent --update --seconds 1 --hitcount 10 --name dns -j DROP
iptables -A INPUT -p tcp --dport 53 -s trusted_networks -j ACCEPT
```

## Detection Methods

### Network Monitoring:
- **Query Analysis**: Monitor unusual DNS query patterns
- **Zone Transfer Attempts**: Detect unauthorized AXFR requests
- **Tunneling Detection**: Identify DNS-based data exfiltration
- **Amplification Prevention**: Rate limiting and source validation

### Log Analysis:
```bash
# BIND log analysis
grep "zone transfer" /var/log/named.log
grep "AXFR" /var/log/named.log
tail -f /var/log/named.log | grep -E "(query|transfer|error)"

# System log monitoring
grep "named" /var/log/syslog
journalctl -u named -f
```

### Anomaly Detection:
- **Query Volume Spikes**: Unusual request patterns
- **Subdomain Brute Force**: Rapid sequential queries
- **Geographic Anomalies**: Queries from unexpected locations
- **Time-based Analysis**: Off-hours reconnaissance activity

## Mitigation Strategies

### DNS Server Hardening:
```
# BIND security configuration
options {
    version "DNS Server";
    recursion no;
    allow-transfer { none; };
    allow-update { none; };
    blackhole { bogus_networks; };
    rate-limit {
        responses-per-second 5;
        window 5;
    };
};
```

### Information Hiding:
- **Minimal Responses**: Reduce information disclosure
- **Version Hiding**: Obscure DNS software versions
- **Split-Horizon DNS**: Different views for internal/external
- **Wildcard Restrictions**: Limit subdomain enumeration

### Monitoring and Response:
- **DNS Security Monitoring**: Real-time query analysis
- **Threat Intelligence**: Integration with DNS reputation feeds
- **Automated Response**: Block suspicious query sources
- **Incident Response**: Procedures for DNS-based attacks

## Advanced Enumeration Techniques

### Passive DNS Analysis:
```bash
# Historical DNS data
# Using passive DNS databases
curl -s "https://api.passivedns.org/query?name=target.com"

# Certificate transparency logs
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq
```

### DNS over HTTPS (DoH) Enumeration:
```bash
# DoH queries
curl -H "accept: application/dns-json" \
"https://cloudflare-dns.com/dns-query?name=target.com&type=A"

# DoH subdomain enumeration
for sub in $(cat subs.txt); do
  curl -s -H "accept: application/dns-json" \
  "https://1.1.1.1/dns-query?name=${sub}.target.com&type=A"
done
```

### IPv6 DNS Enumeration:
```bash
# IPv6 record enumeration
dig target.com AAAA
dnsrecon -d target.com -t aaaa

# IPv6 reverse lookups
dig -x 2001:db8::1
```

## Practical Applications

### Penetration Testing:
- **Reconnaissance Phase**: Map target domain infrastructure
- **Asset Discovery**: Identify all domain-related resources
- **Service Enumeration**: Discover services through DNS
- **Attack Surface Mapping**: Catalog potential entry points

### Red Team Operations:
- **Infrastructure Intelligence**: Understand target network topology
- **Subdomain Takeover**: Identify takeover opportunities
- **Phishing Infrastructure**: Register similar domains
- **Covert Communications**: DNS tunneling for C2

### Security Assessment:
- **DNS Security Audit**: Evaluate DNS configuration security
- **Information Leakage**: Assess data disclosure risks
- **Vulnerability Assessment**: Test for DNS-specific vulnerabilities
- **Compliance Testing**: Verify adherence to DNS security policies

## CEH Exam Focus Points

- Understand DNS protocol fundamentals and record types
- Know key DNS enumeration tools (dig, nslookup, dnsrecon, dnsenum)
- Be familiar with zone transfer concepts and security implications  
- Recognize DNS security features (DNSSEC) and common vulnerabilities
- Understand subdomain enumeration techniques and tools
- Know how to perform reverse DNS lookups and analysis
- Recognize DNS-based attack vectors (cache poisoning, tunneling)
- Understand the role of DNS in reconnaissance and information gathering
