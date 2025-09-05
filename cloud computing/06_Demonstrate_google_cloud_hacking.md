# Google Cloud Platform (GCP) Hacking

## Overview
Google Cloud Platform security testing involves identifying misconfigurations, weak access controls, and vulnerabilities in GCP services. Understanding GCP attack vectors is crucial for both penetration testing and defense.

## Enumerating GCP Resources

### Initial Reconnaissance
- **Service Discovery**: Identify exposed GCP services through DNS enumeration
- **Project Identification**: Discover project IDs through metadata services
- **IAM Enumeration**: List service accounts and roles
- **Resource Mapping**: Identify compute instances, storage buckets, and databases

### Metadata Service Exploitation
```bash
# Access metadata from compute instance
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
-H "Metadata-Flavor: Google"
```

### Project Discovery Techniques
- **DNS Enumeration**: `*.googleapis.com` subdomains
- **Certificate Transparency**: Search for GCP-related certificates
- **GitHub/GitLab**: Search for exposed GCP credentials and project names

## Google Cloud Storage Bucket Enumeration

### Using cloud_enum Tool
cloud_enum automates the discovery of cloud resources across multiple providers including GCP.

#### Installation and Usage
```bash
# Clone and install cloud_enum
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install -r requirements.txt

# Basic enumeration
python3 cloud_enum.py -k example-company
```

#### Advanced Enumeration Techniques
- **Keyword Permutation**: Generate bucket names using company names, domains
- **Common Patterns**: app-backup, company-logs, project-data
- **Subdomain Discovery**: Extract potential bucket names from subdomains

### Manual Bucket Discovery
```bash
# Test bucket existence
curl -s "https://storage.googleapis.com/bucket-name"

# List bucket contents (if publicly readable)
gsutil ls gs://bucket-name
```

## Privilege Escalation Vulnerabilities

### GCP Privilege Escalation Scanner
Automated tool to identify privilege escalation paths in GCP environments.

#### Common Escalation Vectors
- **Service Account Impersonation**: Abuse `iam.serviceAccounts.actAs` permission
- **Cloud Functions**: Deploy malicious functions with elevated privileges
- **Compute Engine**: Exploit default service accounts
- **IAM Policy Misconfigurations**: Overly permissive roles

#### Scanning Techniques
```bash
# Check for privilege escalation paths
./gcp-privesc-scanner.py --project PROJECT_ID --credentials creds.json
```

### Critical Permissions to Identify
- `iam.serviceAccounts.actAs`
- `iam.roles.create`
- `iam.serviceAccounts.setIamPolicy`
- `compute.instances.setServiceAccount`
- `cloudfunctions.functions.create`

## Google Storage Bucket Privilege Escalation

### GCPBucketBrute Tool
Specialized tool for discovering and exploiting GCP storage buckets.

#### Bucket Permission Enumeration
```bash
# Test bucket permissions
gsutil iam get gs://bucket-name

# Check for write permissions
echo "test" | gsutil cp - gs://bucket-name/test.txt
```

#### Common Misconfigurations
- **Public Read Access**: `allUsers` with `roles/storage.objectViewer`
- **Public Write Access**: `allUsers` with `roles/storage.objectCreator`
- **Authenticated Users**: `allAuthenticatedUsers` with excessive permissions

### Exploitation Techniques
- **Data Exfiltration**: Download sensitive files from public buckets
- **Malicious File Upload**: Upload web shells or malware to writable buckets
- **Website Defacement**: Modify static website content in storage buckets

## Maintaining Access and Backdoors

### IAM Role Backdoors
Creating persistent access through IAM roles and service accounts.

#### Service Account Creation
```bash
# Create new service account
gcloud iam service-accounts create backdoor-sa \
--description="Backup service account" \
--display-name="Backup Service"

# Grant necessary permissions
gcloud projects add-iam-policy-binding PROJECT_ID \
--member="serviceAccount:backdoor-sa@PROJECT_ID.iam.gserviceaccount.com" \
--role="roles/editor"
```

#### Cloud Function Backdoors
- **Persistent Functions**: Deploy HTTP-triggered functions for remote access
- **Scheduled Functions**: Create cron-based functions for periodic access
- **Event-triggered Functions**: Deploy functions triggered by storage events

### Key Management Backdoors
- **Service Account Keys**: Generate and download service account keys
- **Custom Roles**: Create roles with specific permissions for persistence
- **Resource-level IAM**: Apply permissions at resource level to avoid detection

## GCPGoat - Vulnerable Infrastructure

### Overview of GCPGoat
GCPGoat is an intentionally vulnerable GCP environment designed for security training and testing.

#### Key Vulnerable Components
- **Misconfigured IAM Policies**: Overly permissive roles and bindings
- **Exposed Storage Buckets**: Publicly accessible sensitive data
- **Vulnerable Cloud Functions**: Functions with security flaws
- **Insecure Compute Instances**: VMs with weak configurations
- **Database Misconfigurations**: Cloud SQL instances with security issues

#### Attack Scenarios in GCPGoat
1. **Initial Access**: Exploit publicly exposed services
2. **Privilege Escalation**: Abuse IAM misconfigurations
3. **Lateral Movement**: Access additional GCP services
4. **Data Exfiltration**: Extract sensitive information
5. **Persistence**: Establish backdoors and maintain access

### Learning Objectives
- **Reconnaissance Techniques**: Practice GCP-specific enumeration
- **Exploitation Methods**: Hands-on experience with real vulnerabilities
- **Detection Evasion**: Understand logging and monitoring limitations
- **Remediation Strategies**: Learn proper security configurations

## Attack Methodologies

### Reconnaissance Phase
1. **External Reconnaissance**: Discover GCP resources from outside
2. **Service Enumeration**: Identify exposed GCP services
3. **Credential Harvesting**: Search for exposed API keys and tokens
4. **Social Engineering**: Target GCP administrators and users

### Exploitation Phase
1. **Initial Access**: Exploit vulnerabilities or use stolen credentials
2. **Environment Mapping**: Understand GCP project structure
3. **Privilege Assessment**: Identify current permissions and limitations
4. **Escalation Attempts**: Use discovered misconfigurations for privilege escalation

### Post-Exploitation Phase
1. **Persistence Establishment**: Create backdoors and alternative access methods
2. **Data Discovery**: Locate sensitive information in storage and databases
3. **Lateral Movement**: Access additional GCP projects and resources
4. **Covering Tracks**: Minimize detection through log manipulation

## Detection and Monitoring Evasion

### GCP Logging Services
- **Cloud Audit Logs**: Administrative and data access logs
- **Cloud Monitoring**: Resource and application monitoring
- **Security Command Center**: Centralized security findings
- **Cloud Asset Inventory**: Resource tracking and management

### Evasion Techniques
- **Log Manipulation**: Modify or delete audit logs where possible
- **Service Account Rotation**: Use multiple service accounts to distribute activity
- **Resource Naming**: Use legitimate-sounding names for malicious resources
- **Timing Attacks**: Perform activities during low-monitoring periods

**Key CEH v13 Exam Points**

**Critical Concepts**
1. **GCP Service Architecture**: Understanding core GCP services and their security implications
2. **IAM Structure**: Master service accounts, roles, and policy inheritance
3. **Storage Security**: Bucket permissions and access controls
4. **Compute Security**: VM security and metadata service exploitation
5. **Network Security**: VPC configurations and firewall rules
6. **Monitoring and Logging**: Understanding GCP's security monitoring capabilities
7. **Privilege Escalation**: Common paths and attack vectors in GCP

**Exam Focus Areas**
- **Metadata Service Exploitation**: Access tokens and instance information
- **Storage Bucket Misconfigurations**: Public access and permission issues
- **IAM Policy Vulnerabilities**: Overly permissive roles and bindings
- **Service Account Abuse**: Impersonation and key management issues
- **Cloud Function Security**: Serverless security vulnerabilities
- **Network Misconfigurations**: Open firewall rules and exposed services
- **Audit Log Analysis**: Understanding what activities generate logs

**Practical Skills**
- Enumerate GCP resources using automated tools
- Identify and exploit storage bucket misconfigurations
- Perform privilege escalation through IAM vulnerabilities
- Create persistent backdoors in GCP environments
- Analyze GCP audit logs for security events
- Recommend appropriate security controls for GCP deployments
- Understand the impact of various GCP misconfigurations
