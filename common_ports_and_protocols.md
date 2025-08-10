# 📌 Common Ports and Protocols – CEH v13 Exam Reference
---
# CEH v13 – Essential Ports to Remember

| Port       | Protocol         | Transport | Description                     | Common Attacks / Tools             |
| ---------- | ---------------- | --------- | -------------------------------- | ----------------------------------- |
| 20, 21     | FTP              | TCP       | File transfers (data/control)   | Brute force, sniffing               |
| 22         | SSH              | TCP       | Secure remote login              | Hydra, SSH key attacks              |
| 23         | Telnet           | TCP       | Unencrypted remote login         | Banner grabbing, credential sniffing|
| 25         | SMTP             | TCP       | Email sending                    | Mail spoofing, relay abuse          |
| 53         | DNS              | TCP/UDP   | Domain resolution                | DNS poisoning, zone transfer        |
| 67, 68     | DHCP             | UDP       | IP assignment                    | Rogue DHCP, DHCP starvation         |
| 69         | TFTP             | UDP       | Trivial file transfer            | Config file theft, firmware dumps   |
| 80         | HTTP             | TCP       | Web traffic                      | SQLi, XSS, web app attacks          |
| 110        | POP3             | TCP       | Email retrieval                  | Credential sniffing, brute force    |
| 111        | RPCbind          | TCP/UDP   | RPC mapping                      | RPC enumeration                     |
| 123        | NTP              | UDP       | Network time protocol            | NTP amplification DDoS              |
| 135        | MS RPC           | TCP       | Microsoft RPC endpoint mapper    | DCOM exploitation, RPC attacks      |
| 137–139    | NetBIOS          | TCP/UDP   | File/printer sharing             | Name poisoning, SMB over NetBIOS    |
| 143        | IMAP             | TCP       | Email access                     | Email credential attacks            |
| 161, 162   | SNMP             | UDP       | Network management               | snmpwalk, community string attacks  |
| 389        | LDAP             | TCP/UDP   | Directory services               | LDAP injection, enumeration         |
| 443        | HTTPS            | TCP       | Secure web traffic               | SSL/TLS attacks, cert bypass        |
| 445        | SMB              | TCP       | File sharing                     | EternalBlue, SMB relay              |
| 500        | ISAKMP/IKE       | UDP       | VPN negotiation                  | VPN MITM, IKE scanning              |
| 514        | Syslog           | UDP       | Logging                          | Log injection, DoS                  |
| 993, 995   | Secure IMAP/POP3 | TCP       | Encrypted email                  | Email SSL/TLS attacks               |
| 1433, 1434 | MS SQL Server    | TCP/UDP   | Databases                        | SQL injection, brute force          |
| 1521       | Oracle TNS       | TCP       | Oracle database listener         | TNS poisoning, SQL injection        |
| 3306       | MySQL            | TCP       | MySQL database                   | SQL injection, brute force          |
| 3389       | RDP              | TCP       | Remote desktop                   | RDP brute force, BlueKeep           |
| 5432       | PostgreSQL       | TCP       | PostgreSQL database              | SQL injection                       |
| 5900       | VNC              | TCP       | Remote control                   | VNC password brute force            |
| 8080       | HTTP Alternate   | TCP       | Proxies/web apps                 | Web proxy bypass, web attacks       |

---
## 🔹 Essential TCP/UDP Ports & Protocols (Knowledge Reference)

| Port | Protocol | Transport | Description | Common Attacks / Tools |
|------|----------|-----------|-------------|------------------------|
| **7** | Echo | TCP/UDP | Echo service | DoS attacks, port scanning |
| **9** | Discard | TCP/UDP | Null service | DoS amplification |
| **13** | Daytime | TCP/UDP | Date/time service | Information gathering |
| **17** | QOTD | TCP/UDP | Quote of the day | DoS amplification |
| **19** | CharGen | TCP/UDP | Character generator | DoS amplification |
| **20** | FTP Data | TCP | Transfers files (active mode) | Brute force, sniffing (Wireshark) |
| **21** | FTP Control | TCP | Controls file transfers | Hydra, Medusa, anonymous login |
| **22** | SSH | TCP | Secure remote login | Hydra, SSH key attacks, user enum |
| **23** | Telnet | TCP | Unencrypted remote login | Banner grabbing, credential sniffing |
| **25** | SMTP | TCP | Send emails | Mail spoofing, phishing, relay testing |
| **37** | Time | TCP/UDP | Time protocol | Information disclosure |
| **42** | WINS | TCP/UDP | Windows name service | NetBIOS name resolution |
| **43** | WHOIS | TCP | Domain registration info | Information gathering |
| **49** | TACACS+ | TCP/UDP | Authentication service | Credential attacks |
| **53** | DNS | TCP/UDP | Domain name resolution | DNS poisoning, zone transfer, tunneling |
| **67** | DHCP Server | UDP | DHCP server responses | Rogue DHCP attacks |
| **68** | DHCP Client | UDP | DHCP client requests | DHCP starvation |
| **69** | TFTP | UDP | Trivial file transfer | Config file theft, firmware dumps |
| **70** | Gopher | TCP | Document retrieval | Rare, legacy protocol |
| **79** | Finger | TCP | User information | User enumeration |
| **80** | HTTP | TCP | Web browsing | SQLi, XSS, web app attacks |
| **88** | Kerberos | TCP/UDP | Authentication protocol | Golden ticket, silver ticket |
| **102** | MS Exchange | TCP | Microsoft Exchange | Email system attacks |
| **110** | POP3 | TCP | Email retrieval | Credential sniffing, brute force |
| **111** | RPCbind | TCP/UDP | RPC port mapper | RPC enumeration, showmount |
| **113** | Ident | TCP | Identity service | Username enumeration |
| **119** | NNTP | TCP | Network news transfer | News server attacks |
| **123** | NTP | UDP | Network time protocol | NTP amplification DDoS |
| **135** | MS RPC | TCP | Microsoft RPC endpoint | DCOM exploitation, RPC attacks |
| **137** | NetBIOS-NS | UDP | NetBIOS name service | Name resolution poisoning |
| **138** | NetBIOS-DGM | UDP | NetBIOS datagram | NetBIOS session hijacking |
| **139** | NetBIOS-SSN | TCP | NetBIOS session | enum4linux, SMB over NetBIOS |
| **143** | IMAP | TCP | Internet mail access | Email credential attacks |
| **153** | SGMP | UDP | Simple gateway monitoring | Network device enumeration |
| **161** | SNMP | UDP | Simple network management | snmpwalk, community string attacks |
| **162** | SNMP Trap | UDP | SNMP notifications | SNMP trap spoofing |
| **179** | BGP | TCP | Border gateway protocol | BGP hijacking, route injection |
| **194** | IRC | TCP | Internet relay chat | Botnet C&C, DCC attacks |
| **389** | LDAP | TCP/UDP | Lightweight directory access | LDAP injection, enumeration |
| **427** | SLP | TCP/UDP | Service location protocol | Service discovery |
| **443** | HTTPS | TCP | Secure HTTP | SSL/TLS attacks, certificate bypass |
| **444** | SNPP | TCP | Simple network paging | Paging system attacks |
| **445** | SMB | TCP | Server message block | EternalBlue, SMB relay, pass-the-hash |
| **464** | Kerberos Password | TCP/UDP | Kerberos password change | Password policy attacks |
| **465** | SMTPS | TCP | Secure SMTP | Email encryption bypass |
| **500** | ISAKMP/IKE | UDP | VPN key exchange | VPN MITM, IKE scanning |
| **512** | rexec | TCP | Remote execution | Legacy remote access |
| **513** | rlogin | TCP | Remote login | Credential theft |
| **514** | RSH | TCP | Remote shell | Command injection |
| **514** | Syslog | UDP | System logging | Log injection, DoS |
| **515** | LPR/LPD | TCP | Line printer daemon | Print server attacks |
| **520** | RIP | UDP | Routing information protocol | Route poisoning |
| **521** | RIPng | UDP | RIP for IPv6 | IPv6 route manipulation |
| **523** | IBM-DB2 | TCP | IBM DB2 database | SQL injection, brute force |
| **540** | UUCP | TCP | Unix-to-unix copy | File transfer attacks |
| **543** | KLogin | TCP | Kerberos login | Authentication bypass |
| **544** | KShell | TCP | Kerberos shell | Remote command execution |
| **546** | DHCPv6 Client | UDP | DHCPv6 client | IPv6 DHCP attacks |
| **547** | DHCPv6 Server | UDP | DHCPv6 server | Rogue DHCPv6 |
| **554** | RTSP | TCP/UDP | Real-time streaming | Media stream hijacking |
| **563** | NNTPS | TCP | Secure NNTP | News server encryption bypass |
| **587** | SMTP Submission | TCP | Email submission | Mail relay abuse |
| **593** | HTTP-RPC-EPMAP | TCP | Microsoft RPC over HTTP | RPC over web attacks |
| **631** | IPP/CUPS | TCP/UDP | Internet printing protocol | Printer exploitation |
| **636** | LDAPS | TCP | Secure LDAP | LDAP over SSL attacks |
| **639** | MSDP | TCP | Multicast source discovery | Multicast attacks |
| **646** | LDP | TCP/UDP | Label distribution protocol | MPLS attacks |
| **691** | MS Exchange | TCP | Microsoft Exchange routing | Exchange server attacks |
| **860** | iSCSI | TCP | Internet SCSI | Storage network attacks |
| **873** | rsync | TCP | File synchronization | Data exfiltration |
| **902** | VMware Auth | TCP | VMware authentication | Hypervisor attacks |
| **989** | FTPS Data | TCP | Secure FTP data | FTP over SSL attacks |
| **990** | FTPS Control | TCP | Secure FTP control | FTP SSL/TLS bypass |
| **993** | IMAPS | TCP | Secure IMAP | Email encryption attacks |
| **995** | POP3S | TCP | Secure POP3 | Email SSL attacks |
| **1025-1029** | Windows RPC | TCP | Windows RPC services | RPC enumeration |
| **1080** | SOCKS | TCP | SOCKS proxy | Proxy bypass, tunneling |
| **1194** | OpenVPN | UDP | VPN service | VPN attacks |
| **1433** | MS SQL Server | TCP | Microsoft SQL database | SQL injection, brute force |
| **1434** | MS SQL Monitor | UDP | SQL Server monitoring | SQL Server discovery |
| **1521** | Oracle TNS | TCP | Oracle database listener | TNS poisoning, SQL injection |
| **1723** | PPTP | TCP | Point-to-point tunneling | VPN attacks |
| **1812/1813** | RADIUS | UDP | Authentication service | RADIUS attacks |
| **2049** | NFS | TCP/UDP | Network file system | File system attacks, showmount |
| **2121** | FTP (Alternate) | TCP | Alternative FTP port | FTP attacks on non-standard port |
| **2375/2376** | Docker | TCP | Docker daemon | Container attacks |
| **2483/2484** | Oracle DB | TCP | Oracle database (alternate) | Database attacks |
| **3260** | iSCSI | TCP | Internet SCSI target | Storage attacks |
| **3306** | MySQL | TCP | MySQL database | SQL injection, brute force |
| **3389** | RDP | TCP | Remote desktop protocol | RDP brute force, BlueKeep |
| **3690** | Subversion | TCP | SVN version control | Source code theft |
| **4443** | Pharos | TCP | Pharos print server | Print server attacks |
| **5000** | UPnP | TCP | Universal plug and play | UPnP attacks |
| **5038** | Asterisk | TCP | Asterisk management | VoIP attacks |
| **5060/5061** | SIP | TCP/UDP | Session initiation protocol | VoIP attacks, call hijacking |
| **5432** | PostgreSQL | TCP | PostgreSQL database | SQL injection |
| **5500** | VNC HTTP | TCP | VNC over HTTP | VNC password attacks |
| **5631** | pcANYWHERE | TCP | Symantec remote control | Remote access attacks |
| **5666** | NRPE | TCP | Nagios remote plugin | Monitoring system attacks |
| **5800** | VNC HTTP | TCP | VNC web interface | VNC attacks |
| **5900** | VNC | TCP | Virtual network computing | VNC password brute force |
| **5984/5985** | CouchDB | TCP | CouchDB database | NoSQL injection |
| **5985** | WinRM HTTP | TCP | Windows remote management | PowerShell remoting |
| **5986** | WinRM HTTPS | TCP | Secure Windows remote mgmt | Encrypted remoting attacks |
| **6000** | X11 | TCP | X Window system | X11 forwarding attacks |
| **6379** | Redis | TCP | Redis database | Redis attacks, data theft |
| **6660-6669** | IRC | TCP | Internet relay chat | IRC botnet C&C |
| **7000/7001** | Cassandra | TCP | Cassandra database | NoSQL attacks |
| **8000** | HTTP Alternate | TCP | Alternative web server | Web application attacks |
| **8008** | HTTP Alternate | TCP | Alternative web server | Proxy attacks |
| **8020** | Hadoop NameNode | TCP | Hadoop file system | Big data attacks |
| **8080** | HTTP Proxy | TCP | Web proxy/alternate HTTP | Web proxy bypass |
| **8443** | HTTPS Alternate | TCP | Alternative HTTPS | SSL certificate bypass |
| **8834** | Nessus | TCP | Nessus vulnerability scanner | Scanner exploitation |
| **9000** | SonarQube | TCP | Code quality management | Code analysis attacks |
| **9042** | Cassandra | TCP | Cassandra CQL | NoSQL injection |
| **9050** | Tor SOCKS | TCP | Tor proxy | Anonymous communication |
| **9051** | Tor Control | TCP | Tor control port | Tor network manipulation |
| **9100** | JetDirect | TCP | HP printer protocol | Printer attacks |
| **9200/9300** | Elasticsearch | TCP | Search engine | Data exfiltration |
| **9418** | Git | TCP | Git version control | Source code theft |
| **10000** | Webmin | TCP | Web-based admin | Admin panel exploitation |
| **10050** | Zabbix Agent | TCP | Monitoring agent | Monitoring system attacks |
| **10051** | Zabbix Server | TCP | Monitoring server | Infrastructure monitoring attacks |
| **11211** | Memcached | TCP/UDP | Memory caching | Cache poisoning, DDoS amplification |
| **27017/27018** | MongoDB | TCP | MongoDB database | NoSQL injection |
| **50000** | SAP | TCP | SAP application server | ERP system attacks |

---

## 🔹 Well-Known Port Ranges

| Range | Description | Security Implications |
|-------|-------------|---------------------|
| **0-1023** | Well-known/System ports | Require root/admin privileges to bind |
| **1024-49151** | Registered/User ports | User applications, less privileged |
| **49152-65535** | Dynamic/Private ports | Ephemeral ports, client connections |

---

## 🔹 Protocol Categories for CEH v13

### **Database Protocols**
- **1433** - Microsoft SQL Server
- **1521** - Oracle TNS Listener  
- **3306** - MySQL
- **5432** - PostgreSQL
- **6379** - Redis
- **9042** - Cassandra CQL
- **27017** - MongoDB

### **Email Protocols**
- **25** - SMTP (Send)
- **110** - POP3 (Retrieve)
- **143** - IMAP (Access)
- **465** - SMTPS (Secure Send)
- **587** - SMTP Submission
- **993** - IMAPS (Secure Access)
- **995** - POP3S (Secure Retrieve)

### **File Transfer Protocols**
- **20/21** - FTP (File Transfer)
- **22** - SFTP/SCP (Secure File Transfer)
- **69** - TFTP (Trivial File Transfer)
- **873** - rsync (Synchronization)
- **989/990** - FTPS (Secure FTP)
- **2049** - NFS (Network File System)

### **Remote Access Protocols**
- **22** - SSH (Secure Shell)
- **23** - Telnet (Unsecure Remote)
- **3389** - RDP (Remote Desktop)
- **5900** - VNC (Virtual Network Computing)
- **5985/5986** - WinRM (Windows Remote Management)

### **Web Protocols**
- **80** - HTTP (Web)
- **443** - HTTPS (Secure Web)
- **8000/8008/8080** - HTTP Alternates
- **8443** - HTTPS Alternate

### **Directory Services**
- **389** - LDAP (Lightweight Directory)
- **636** - LDAPS (Secure LDAP)
- **88** - Kerberos (Authentication)

### **Network Management**
- **161/162** - SNMP (Network Management)
- **514** - Syslog (Logging)
- **123** - NTP (Time Synchronization)

### **VoIP/Media Protocols**
- **5060/5061** - SIP (Session Initiation)
- **554** - RTSP (Streaming)

### **Virtualization/Container**
- **902** - VMware Authentication
- **2375/2376** - Docker Daemon

---

## 🔹 CEH v13 Exam Attack Vectors by Port

### **High-Risk Ports (Frequent Exam Topics)**
- **21 (FTP)** - Anonymous login, brute force
- **22 (SSH)** - Key-based attacks, user enumeration  
- **23 (Telnet)** - Credential sniffing
- **25 (SMTP)** - Email spoofing, open relay
- **53 (DNS)** - Zone transfer, cache poisoning
- **80/443 (HTTP/S)** - Web application attacks
- **135 (RPC)** - DCOM exploitation
- **139/445 (SMB)** - EternalBlue, relay attacks
- **161 (SNMP)** - Community string attacks
- **389 (LDAP)** - LDAP injection
- **1433 (MSSQL)** - SQL injection
- **3389 (RDP)** - Remote desktop brute force

### **IoT/Modern Service Ports**
- **1883** - MQTT (IoT messaging)
- **5683** - CoAP (Constrained application)
- **6379** - Redis (In-memory database)
- **9200** - Elasticsearch (Search engine)
- **27017** - MongoDB (Document database)

---

## 🔹 Quick Command Reference

### **Port Scanning**
```bash
# Basic port scan
nmap -p- target

# Service version detection
nmap -sV -p 21,22,23,25,53,80,110,443,993,995 target

# Top 1000 ports
nmap --top-ports 1000 target
```

### **Service Enumeration**
```bash
# Banner grabbing
nc -nv target 21
telnet target 25

# SNMP enumeration
snmpwalk -c public -v1 target

# SMB enumeration
enum4linux target
```

---

## 🔹 Exam Tips
- **Memorize common ports:** 21, 22, 23, 25, 53, 80, 110, 443, 993, 995
- **Know attack vectors** for each major service
- **Understand protocol differences** (TCP vs UDP)
- **Practice banner grabbing** and service identification
- **Focus on database ports** (1433, 3306, 5432, 27017)
- **Remember alternative ports** (8080, 8443, 2121)

---
