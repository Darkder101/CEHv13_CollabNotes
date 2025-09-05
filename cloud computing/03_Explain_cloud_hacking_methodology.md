# Cloud Hacking Methodology - CEH v13

## Information Gathering

### Identifying Target Cloud Environment

#### Cloud Provider Identification
- **DNS Analysis**: Analyze DNS records to identify cloud providers
  - AWS: amazonaws.com domains, ELB endpoints
  - Azure: azurewebsites.net, cloudapp.net, blob.core.windows.net
  - GCP: googleusercontent.com, appspot.com, storage.googleapis.com
- **IP Range Analysis**: Check IP addresses against known cloud provider ranges
- **Certificate Analysis**: SSL certificates may reveal cloud infrastructure
- **Response Headers**: Server headers may indicate cloud services

#### Service Discovery Techniques
- **Subdomain Enumeration**: Find cloud services through subdomain discovery
  - Tools: Subfinder, Amass, Sublist3r
  - Targets: S3 buckets, Azure blobs, GCP storage buckets
- **DNS Zone Walking**: Enumerate DNS records for cloud resources
- **Google Dorking**: Use search engines to find exposed cloud resources
- **Shodan/Censys**: Search for cloud services and exposed databases

#### Information Sources
- **WHOIS Data**: Domain registration information
- **Public Code Repositories**: GitHub, GitLab for configuration files
- **Company Websites**: Technology stack information
- **Social Media**: Employee posts about cloud infrastructure
- **Job Postings**: Technology requirements and cloud platforms used

#### Reconnaissance Tools
- **CloudEnum**: Multi-cloud enumeration tool
- **CloudMapper**: AWS account reconnaissance
- **Recon-ng**: Web reconnaissance framework with cloud modules
- **TheHarvester**: Email, subdomain, and host gathering

### Discovering Open Ports and Services Using Masscan

#### Masscan Overview
- **Purpose**: High-speed port scanner for large-scale network reconnaissance
- **Speed**: Can scan millions of ports per second
- **Capability**: TCP/UDP port scanning, banner grabbing
- **Use Case**: Initial network reconnaissance of cloud infrastructure

#### Basic Masscan Commands
```bash
# Basic port scan
masscan -p1-65535 target_ip --rate=1000

# Specific port ranges
masscan -p21,22,80,443,3389 target_range --rate=1000

# UDP scanning
masscan -pU:53,161,162 target_ip --rate=1000

# Output to file
masscan -p80,443 target_ip --rate=1000 -oG output.txt
```

#### Cloud-Specific Scanning Techniques
- **AWS Ranges**: Scan known AWS IP ranges for exposed services
- **Azure Ranges**: Target Azure IP blocks for open ports
- **GCP Ranges**: Enumerate Google Cloud IP ranges
- **CDN Detection**: Identify CDN endpoints and origin servers

#### Service Identification
- **Common Cloud Ports**: 22 (SSH), 80/443 (HTTP/HTTPS), 3389 (RDP), 5432 (PostgreSQL)
- **Database Ports**: 3306 (MySQL), 5432 (PostgreSQL), 1433 (SQL Server), 27017 (MongoDB)
- **Management Ports**: 8080, 8443, 9090 (Management interfaces)
- **Container Ports**: 2375/2376 (Docker), 8080 (Kubernetes)

#### Advanced Scanning Techniques
- **Banner Grabbing**: Capture service banners for version identification
- **Rate Limiting**: Avoid detection with appropriate scan rates
- **Source IP Rotation**: Use multiple source IPs to evade blocking
- **Timing Controls**: Adjust timing to avoid triggering security controls

## Vulnerability Assessment

### Vulnerability Scanner Using Prowler

#### Prowler Overview
- **Purpose**: AWS security assessment tool based on CIS benchmarks
- **Coverage**: 200+ security checks across AWS services
- **Compliance**: CIS, GDPR, HIPAA, ISO27001, AWS Well-Architected Framework
- **Output**: HTML, JSON, CSV reports with findings and remediation

#### Key Assessment Areas
- **IAM**: Identity and access management misconfigurations
- **S3**: Bucket permissions, encryption, logging
- **VPC**: Network security groups, NACLs, flow logs
- **EC2**: Instance security, AMI configurations
- **RDS**: Database security, encryption, backups
- **CloudTrail**: Audit logging configuration
- **KMS**: Key management and encryption policies

#### Prowler Usage Examples
```bash
# Basic AWS account scan
./prowler -p aws_profile_name

# Specific service assessment
./prowler -p aws_profile_name -s s3

# Custom checks only
./prowler -p aws_profile_name -c check11,check12

# Generate HTML report
./prowler -p aws_profile_name -M html

# Multi-region scan
./prowler -p aws_profile_name -f us-east-1,eu-west-1
```

#### Critical Findings Categories
- **High Severity**: Public S3 buckets, overprivileged IAM policies
- **Medium Severity**: Missing encryption, inadequate logging
- **Low Severity**: Optimization recommendations, best practices
- **Informational**: Configuration details, compliance status

### Identifying Misconfiguration in Cloud Resources Using CloudSploit

#### CloudSploit Overview
- **Multi-Cloud**: Supports AWS, Azure, GCP, Oracle Cloud
- **Automation**: Automated security scanning and assessment
- **Compliance**: Maps findings to compliance frameworks
- **Integration**: API-based scanning with CI/CD integration

#### Supported Cloud Providers
- **AWS**: Comprehensive service coverage including IAM, S3, EC2, RDS
- **Azure**: Virtual machines, storage accounts, key vaults, networking
- **GCP**: Compute Engine, Cloud Storage, IAM, networking
- **Multi-Cloud**: Cross-platform security assessment capabilities

#### Common Misconfigurations Detected
- **Storage**: Public buckets, unencrypted data, weak access controls
- **Network**: Open security groups, missing network ACLs
- **Identity**: Weak password policies, excessive permissions
- **Encryption**: Unencrypted resources, weak encryption keys
- **Monitoring**: Missing logging, inadequate alerting

#### CloudSploit Usage
```bash
# Install CloudSploit
npm install -g cloudsploit

# AWS scan with credentials
cloudsploit --cloud aws --compliance hipaa

# Azure scan
cloudsploit --cloud azure --subscription-id <id>

# GCP scan
cloudsploit --cloud gcp --project-id <project>

# Custom plugin execution
cloudsploit --cloud aws --plugin s3BucketAllUsersPolicy
```

#### Assessment Categories
- **Security**: Vulnerabilities and security weaknesses
- **Compliance**: Regulatory and framework compliance
- **Cost**: Resource optimization opportunities
- **Performance**: Configuration performance impacts
- **Operational**: Best practices and operational efficiency

#### Remediation Guidance
- **Prioritization**: Risk-based finding prioritization
- **Remediation Steps**: Detailed fix instructions
- **Automation**: Infrastructure-as-code remediation
- **Validation**: Post-remediation verification steps

## Exploitation

### Pre-Exploitation Activities
- **Credential Harvesting**: Collect credentials from reconnaissance
- **Access Vector Identification**: Determine initial access methods
- **Target Prioritization**: Focus on high-value assets
- **Tool Preparation**: Prepare exploitation tools and frameworks

### Common Exploitation Techniques

#### Credential-Based Attacks
- **Password Spraying**: Test common passwords against multiple accounts
- **Credential Stuffing**: Use leaked credentials across multiple services
- **Brute Force**: Systematic password guessing attacks
- **Token Theft**: Steal authentication tokens and session cookies

#### Service-Specific Exploits
- **S3 Bucket Exploitation**: Access misconfigured storage buckets
- **API Abuse**: Exploit weak API authentication and authorization
- **Container Escape**: Break out of container isolation
- **Privilege Escalation**: Escalate permissions within cloud services

#### Network-Based Attacks
- **Man-in-the-Middle**: Intercept cloud communications
- **DNS Hijacking**: Redirect traffic to malicious servers
- **Network Pivoting**: Use compromised resources to attack others
- **Lateral Movement**: Spread through cloud infrastructure

### Exploitation Tools and Frameworks
- **Metasploit**: Exploitation framework with cloud modules
- **Pacu**: AWS exploitation framework
- **ScoutSuite**: Multi-cloud security auditing tool
- **CloudGoat**: Vulnerable cloud infrastructure for testing

### Post-Initial Access
- **Persistence Establishment**: Maintain access to compromised resources
- **Privilege Escalation**: Gain higher-level permissions
- **Data Discovery**: Locate and access sensitive information
- **Lateral Movement**: Expand access to other cloud resources

## Post-Exploitation

### Cleanup and Maintaining Stealth

#### Log Manipulation
- **Log Deletion**: Remove evidence of unauthorized activities
- **Log Tampering**: Modify logs to hide attack traces
- **Timestamp Modification**: Alter timestamps to confuse forensics
- **Log Forwarding**: Redirect logs to prevent collection

#### Stealth Techniques
- **Living off the Land**: Use legitimate cloud services for malicious purposes
- **Process Hollowing**: Hide malicious processes within legitimate ones
- **Rootkit Installation**: Install persistent backdoors
- **Communication Channels**: Establish covert communication methods

#### Evidence Elimination
- **Temporary File Cleanup**: Remove temporary files and caches
- **History Clearing**: Clear command history and browser data
- **Network Trace Removal**: Eliminate network connection evidence
- **Artifact Deletion**: Remove malware and exploitation tools

#### Persistence Mechanisms
- **Backdoor Accounts**: Create hidden administrative accounts
- **Scheduled Tasks**: Use cloud automation for persistence
- **API Keys**: Generate persistent access tokens
- **Infrastructure Modification**: Alter security configurations

### Anti-Forensics Techniques

#### Data Obfuscation
- **Encryption**: Encrypt stolen data and communications
- **Steganography**: Hide data within legitimate files
- **Compression**: Compress data to reduce detection
- **Fragmentation**: Split data across multiple locations

#### Timeline Manipulation
- **Clock Skewing**: Modify system clocks to confuse timeline analysis
- **Batch Operations**: Perform actions in bulk to obscure individual activities
- **Delayed Execution**: Use scheduled tasks to delay suspicious activities
- **False Flag Operations**: Create misleading evidence pointing to other actors

#### Communication Security
- **Encrypted Channels**: Use encrypted communication protocols
- **Domain Fronting**: Hide traffic behind legitimate domains
- **DNS Tunneling**: Use DNS for covert communication
- **Tor/VPN Usage**: Anonymize network connections

#### Operational Security (OPSEC)
- **Attribution Avoidance**: Prevent identification and attribution
- **Tool Sanitization**: Remove identifying information from tools
- **Infrastructure Compartmentalization**: Separate attack infrastructure
- **Counter-Intelligence**: Mislead defenders and investigators

### Advanced Persistence Techniques

#### Cloud-Native Persistence
- **Serverless Functions**: Use Lambda/Azure Functions for persistence
- **Container Images**: Embed backdoors in container images
- **Infrastructure as Code**: Modify IaC templates for persistent access
- **API Gateway Abuse**: Create persistent API endpoints

#### Credential Management
- **Token Refresh**: Maintain valid authentication tokens
- **Certificate Abuse**: Use stolen certificates for authentication
- **Service Account Creation**: Generate persistent service accounts
- **Federation Abuse**: Abuse identity federation for persistence

#### Resource Utilization
- **Resource Hijacking**: Use victim's cloud resources for attacker purposes
- **Cryptojacking**: Mine cryptocurrency using compromised resources
- **Botnet Infrastructure**: Use cloud resources for botnet operations
- **Data Exfiltration**: Slowly exfiltrate data to avoid detection

---

## Key CEH v13 Exam Points

### Critical Concepts
1. **Methodology Phases**: Understand the systematic approach to cloud penetration testing
2. **Reconnaissance Techniques**: Master cloud provider identification and service discovery
3. **Vulnerability Assessment**: Know tools like Prowler and CloudSploit for different cloud platforms
4. **Exploitation Methods**: Understand cloud-specific attack vectors and techniques
5. **Post-Exploitation**: Master persistence, stealth, and anti-forensics techniques
6. **Tool Proficiency**: Familiarity with Masscan, Prowler, CloudSploit, and cloud-native tools
7. **Stealth Operations**: Understand how to maintain persistence while avoiding detection

### Exam Focus Areas
* **Information Gathering**: DNS analysis, subdomain enumeration, cloud provider identification
* **Port Scanning**: Masscan usage, service discovery, rate limiting techniques
* **Vulnerability Assessment**: Prowler for AWS, CloudSploit for multi-cloud environments
* **Exploitation Techniques**: Credential attacks, service exploits, privilege escalation
* **Post-Exploitation**: Log manipulation, persistence mechanisms, anti-forensics
* **Stealth Techniques**: Living off the land, communication channels, OPSEC principles
* **Cloud Provider Recognition**: Identifying AWS, Azure, GCP services and infrastructure

### Practical Skills
* Perform comprehensive cloud reconnaissance using multiple techniques
* Execute vulnerability assessments with appropriate tools for different cloud platforms
* Identify and exploit common cloud misconfigurations and vulnerabilities  
* Implement post-exploitation techniques for persistence and stealth
* Understand the attack lifecycle specific to cloud environments
* Recognize indicators of compromise and attack techniques in cloud logs
* Apply appropriate tools and techniques for each phase of cloud penetration testing
