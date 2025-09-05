# Cloud Computing Threats - CEH v13

## OWASP Top 10 Cloud Security Risks

### 1. Accountability and Data Ownership
- **Risk**: Unclear responsibility for data protection and compliance
- **Issues**: Data location uncertainty, jurisdictional challenges, audit trails
- **Impact**: Compliance violations, legal liability, regulatory penalties
- **Mitigation**: Clear contracts, data classification, audit mechanisms

### 2. User Identity Federation
- **Risk**: Inadequate identity and access management across cloud services
- **Issues**: Single sign-on vulnerabilities, identity provider compromise
- **Threats**: Account takeover, privilege escalation, unauthorized access
- **Controls**: Strong authentication, MFA, identity governance

### 3. Regulatory Compliance
- **Risk**: Failure to meet industry and government regulations
- **Challenges**: Data residency, audit requirements, compliance frameworks
- **Examples**: GDPR, HIPAA, SOX, PCI DSS compliance issues
- **Solutions**: Compliance monitoring, regular audits, policy enforcement

### 4. Business Continuity and Resiliency
- **Risk**: Service disruptions and inadequate disaster recovery
- **Threats**: Provider outages, natural disasters, cyber attacks
- **Impact**: Business interruption, data loss, revenue impact
- **Planning**: Backup strategies, failover mechanisms, recovery testing

### 5. User Privacy and Secondary Usage of Data
- **Risk**: Unauthorized use or exposure of personal and sensitive data
- **Concerns**: Data mining, profiling, third-party data sharing
- **Legal Issues**: Privacy violations, consent management
- **Protection**: Data anonymization, usage agreements, privacy controls

### 6. Service and Data Integration
- **Risk**: Insecure integration between cloud services and systems
- **Issues**: API vulnerabilities, data synchronization, authentication bypass
- **Threats**: Data breaches, system compromise, service disruption
- **Security**: Secure APIs, integration testing, data validation

### 7. Multi-Tenancy and Physical Security
- **Risk**: Inadequate isolation between tenants sharing infrastructure
- **Threats**: Data leakage, cross-tenant attacks, resource interference
- **Physical**: Unauthorized access to data centers, hardware tampering
- **Controls**: Logical separation, encryption, physical security measures

### 8. Incident Analysis and Forensic Support
- **Risk**: Limited ability to investigate security incidents
- **Challenges**: Log accessibility, chain of custody, evidence preservation
- **Legal**: eDiscovery limitations, jurisdictional issues
- **Requirements**: Incident response planning, forensic capabilities

### 9. Infrastructure Security
- **Risk**: Vulnerabilities in underlying cloud infrastructure
- **Areas**: Hypervisor security, network isolation, patch management
- **Threats**: VM escape, network attacks, privilege escalation
- **Defense**: Security hardening, monitoring, vulnerability management

### 10. Non-Production Environment Exposure
- **Risk**: Insecure development, testing, and staging environments
- **Issues**: Default credentials, open access, sensitive data in test environments
- **Impact**: Data exposure, unauthorized access, production compromise
- **Controls**: Environment isolation, data masking, access restrictions

## OWASP Top 10 Kubernetes Risks

### 1. Insecure Workload Configurations
- **Risk**: Misconfigured pods, containers, and workloads
- **Issues**: Privileged containers, excessive permissions, resource limits
- **Threats**: Container escape, resource exhaustion, privilege escalation
- **Controls**: Security policies, admission controllers, configuration validation

### 2. Supply Chain Vulnerabilities
- **Risk**: Compromised container images and components
- **Sources**: Base images, third-party packages, malicious registries
- **Impact**: Malware deployment, backdoors, vulnerable dependencies
- **Mitigation**: Image scanning, trusted registries, SBOM tracking

### 3. Overly Permissive RBAC Configurations
- **Risk**: Excessive permissions granted to users and service accounts
- **Issues**: Cluster-admin access, wildcard permissions, privilege creep
- **Threats**: Unauthorized access, lateral movement, data exfiltration
- **Principle**: Least privilege, regular access reviews, permission auditing

### 4. Lack of Centralized Policy Enforcement
- **Risk**: Inconsistent security policies across cluster resources
- **Problems**: Ad hoc configurations, policy drift, compliance gaps
- **Impact**: Security inconsistencies, regulatory violations
- **Solutions**: Policy engines (OPA Gatekeeper), centralized governance

### 5. Inadequate Logging and Monitoring
- **Risk**: Insufficient visibility into cluster activities and security events
- **Gaps**: Missing audit logs, inadequate alerting, log retention
- **Consequences**: Undetected attacks, delayed incident response
- **Requirements**: Comprehensive logging, SIEM integration, monitoring

### 6. Broken Authentication Mechanisms
- **Risk**: Weak authentication and authorization controls
- **Issues**: Weak credentials, anonymous access, token mismanagement
- **Attacks**: Authentication bypass, token theft, impersonation
- **Security**: Strong authentication, certificate management, token rotation

### 7. Missing Network Segmentation Controls
- **Risk**: Inadequate network isolation between cluster components
- **Problems**: Flat networks, unrestricted pod communication
- **Threats**: Lateral movement, data exfiltration, network attacks
- **Controls**: Network policies, service mesh, micro-segmentation

### 8. Secrets Management Failures
- **Risk**: Insecure handling of sensitive information
- **Issues**: Hardcoded secrets, plain-text storage, excessive access
- **Impact**: Credential compromise, unauthorized access, data breaches
- **Management**: Secret management tools, encryption, rotation policies

### 9. Misconfigured Cluster Components
- **Risk**: Insecure configuration of Kubernetes components
- **Components**: API server, etcd, kubelet, networking
- **Vulnerabilities**: Default settings, disabled security features
- **Hardening**: Security benchmarks (CIS), configuration validation

### 10. Outdated and Vulnerable Kubernetes Components
- **Risk**: Running vulnerable versions of Kubernetes and components
- **Issues**: Unpatched vulnerabilities, legacy versions, update delays
- **Exposure**: Known exploits, security bypasses
- **Management**: Regular updates, vulnerability scanning, patch management

## OWASP Top 10 Serverless Security Risks

### 1. Injection Flaws
- **Types**: SQL injection, NoSQL injection, command injection, LDAP injection
- **Context**: Serverless functions processing untrusted input
- **Impact**: Data manipulation, system compromise, privilege escalation
- **Prevention**: Input validation, parameterized queries, least privilege

### 2. Broken Authentication
- **Issues**: Weak authentication mechanisms, session management flaws
- **Risks**: Account takeover, unauthorized access, identity spoofing
- **Context**: API authentication, JWT vulnerabilities, OAuth misuse
- **Controls**: Strong authentication, secure session management, MFA

### 3. Insecure Serverless Deployment Configuration
- **Problems**: Overprivileged functions, public access, debug settings
- **Misconfigurations**: Wide permissions, unnecessary services, verbose logging
- **Impact**: Data exposure, privilege escalation, resource abuse
- **Security**: Principle of least privilege, secure defaults, configuration review

### 4. Over-Privileged Function Permissions and Roles
- **Risk**: Functions granted excessive permissions beyond requirements
- **Issues**: Broad IAM policies, wildcard permissions, inherited privileges
- **Consequences**: Lateral movement, data access, service compromise
- **Mitigation**: Minimal permissions, regular audits, permission boundaries

### 5. Inadequate Function Monitoring and Logging
- **Problems**: Insufficient logging, missing security events, log retention
- **Impact**: Undetected attacks, compliance violations, forensic limitations
- **Requirements**: Comprehensive logging, real-time monitoring, alerting
- **Tools**: Cloud logging services, SIEM integration, anomaly detection

### 6. Insecure Third-Party Dependencies
- **Risk**: Vulnerable libraries and packages in function code
- **Sources**: NPM packages, Python libraries, container base images
- **Impact**: Code execution, data breaches, supply chain attacks
- **Management**: Dependency scanning, regular updates, vulnerability tracking

### 7. Insecure Application Secrets Storage
- **Problems**: Hardcoded secrets, environment variables, plain-text storage
- **Types**: API keys, database credentials, encryption keys
- **Exposure**: Code repositories, function configurations, memory dumps
- **Solutions**: Secret management services, encryption, rotation

### 8. Denial of Wallet (Economic DoS)
- **Concept**: Attacks causing excessive billing through resource consumption
- **Methods**: Infinite loops, recursive calls, resource-intensive operations
- **Impact**: Financial damage, service degradation, budget exhaustion
- **Protection**: Resource limits, cost monitoring, timeout controls

### 9. Improper Exception Handling and Verbose Error Messages
- **Risk**: Information disclosure through error messages
- **Exposure**: System details, file paths, database schemas
- **Impact**: Information gathering for attacks, security bypass
- **Controls**: Generic error messages, proper exception handling, log sanitization

### 10. Functions with Improper Controls for Regular Expressions
- **Risk**: ReDoS (Regular Expression Denial of Service) attacks
- **Cause**: Inefficient regex patterns causing exponential backtracking
- **Impact**: Function timeout, resource exhaustion, service denial
- **Prevention**: Regex validation, timeout limits, pattern optimization

## Cloud Computing Threats

### Data Breaches
- **Causes**: Misconfigurations, weak access controls, insider threats
- **Impact**: Confidential data exposure, regulatory violations, reputation damage
- **Vectors**: Unsecured storage, API vulnerabilities, credential compromise
- **Prevention**: Encryption, access controls, monitoring, incident response

### Account Hijacking
- **Methods**: Credential stuffing, phishing, session hijacking, social engineering
- **Impact**: Unauthorized access, data theft, resource abuse, reputation damage
- **Targets**: Administrative accounts, service accounts, user credentials
- **Protection**: MFA, strong passwords, account monitoring, anomaly detection

### Insider Threats
- **Types**: Malicious insiders, negligent users, compromised accounts
- **Access**: Privileged access, data access, system modifications
- **Impact**: Data theft, sabotage, fraud, intellectual property loss
- **Controls**: Access governance, behavior monitoring, separation of duties

### Insecure APIs
- **Vulnerabilities**: Authentication flaws, authorization bypass, injection attacks
- **Exposure**: Data access, system compromise, service disruption
- **Types**: REST APIs, GraphQL, webhook endpoints, management interfaces
- **Security**: API security testing, rate limiting, input validation

### DoS and DDoS Attacks
- **Targets**: Cloud services, applications, APIs, network infrastructure
- **Methods**: Volumetric attacks, protocol attacks, application-layer attacks
- **Impact**: Service unavailability, performance degradation, financial loss
- **Mitigation**: DDoS protection services, rate limiting, traffic filtering

### System Vulnerabilities
- **Sources**: Operating systems, applications, services, configurations
- **Types**: Unpatched systems, zero-day exploits, misconfigurations
- **Impact**: System compromise, data breaches, service disruption
- **Management**: Vulnerability scanning, patch management, configuration hardening

## Container Vulnerabilities

### Image Vulnerabilities
- **Base Image Flaws**: Vulnerable operating system packages and libraries
- **Application Dependencies**: Outdated or vulnerable application components
- **Malicious Images**: Backdoors, malware, cryptocurrency miners
- **Supply Chain**: Compromised build processes and registries
- **Detection**: Container image scanning, vulnerability databases

### Runtime Vulnerabilities
- **Container Escape**: Breaking out of container isolation to host system
- **Privilege Escalation**: Gaining elevated permissions within containers
- **Resource Exhaustion**: DoS through CPU, memory, or disk consumption
- **Network Attacks**: Container-to-container lateral movement
- **Mitigation**: Runtime security monitoring, resource limits, network policies

### Configuration Vulnerabilities
- **Privileged Containers**: Running containers with excessive privileges
- **Host Mount Points**: Mounting sensitive host directories
- **Network Exposure**: Unnecessary port exposure and service access
- **Default Credentials**: Using default passwords and certificates
- **Hardening**: Security policies, least privilege, configuration scanning

### Registry Security Issues
- **Unauthorized Access**: Weak authentication to container registries
- **Image Tampering**: Modification of images after creation
- **Malicious Uploads**: Uploading compromised or malicious images
- **Credential Exposure**: Registry credentials in code or configurations
- **Controls**: Access controls, image signing, vulnerability scanning

## Kubernetes Vulnerabilities

### Control Plane Vulnerabilities
- **API Server**: Authentication bypass, authorization flaws, DoS attacks
- **etcd**: Data exposure, unauthorized access, cluster compromise
- **Scheduler**: Resource starvation, malicious pod placement
- **Controller Manager**: Privilege escalation, resource manipulation
- **Security**: Hardening guides, access controls, network isolation

### Node Vulnerabilities
- **kubelet**: Unauthorized access, container runtime compromise
- **Container Runtime**: Docker/containerd vulnerabilities, escape attacks
- **Network Plugins**: CNI vulnerabilities, network isolation bypass
- **Host OS**: Kernel vulnerabilities, privilege escalation
- **Protection**: Node hardening, runtime security, patch management

### Workload Vulnerabilities
- **Pod Security**: Privileged pods, host network access, volume mounts
- **Service Accounts**: Excessive permissions, token exposure
- **Network Policies**: Missing or inadequate network segmentation
- **Resource Limits**: DoS through resource exhaustion
- **Controls**: Pod Security Standards, RBAC, network policies

### Configuration Vulnerabilities
- **RBAC Misconfigurations**: Overprivileged roles, wildcard permissions
- **Secret Management**: Exposed secrets, weak encryption
- **Network Security**: Open ports, unrestricted communication
- **Admission Control**: Missing or weak admission controllers
- **Governance**: Security policies, configuration validation, compliance

## Cloud Attacks

### Service Hijacking Using Social Engineering
- **Methods**: Phishing, pretexting, baiting, quid pro quo
- **Targets**: Cloud administrators, developers, support personnel
- **Information**: Credentials, access codes, security questions
- **Impact**: Account takeover, data theft, service disruption
- **Prevention**: Security awareness, verification procedures, MFA

### Service Hijacking Using Network Sniffing
- **Techniques**: Packet capture, man-in-the-middle attacks, ARP poisoning
- **Targets**: Authentication traffic, API communications, management interfaces
- **Data**: Credentials, session tokens, sensitive communications
- **Impact**: Unauthorized access, data interception, session hijacking
- **Protection**: Encryption (TLS/SSL), secure protocols, network monitoring

### Side Channel Attacks or Cross Guest VM Breaches
- **Methods**: Timing attacks, cache attacks, electromagnetic analysis
- **Context**: Multi-tenant cloud environments, shared infrastructure
- **Information**: Cryptographic keys, sensitive data, process information
- **Impact**: Data leakage, cryptographic bypass, tenant isolation breach
- **Mitigation**: Hardware isolation, secure coding, monitoring

### Wrapping Attack
- **Technique**: XML signature wrapping in SOAP web services
- **Process**: Manipulating XML structure while preserving valid signatures
- **Target**: Cloud services using XML-based authentication
- **Impact**: Authentication bypass, unauthorized access, data manipulation
- **Defense**: XML signature validation, secure parsing, input validation

### Man-in-the-Cloud (MITC) Attack
- **Method**: Compromising cloud storage synchronization tokens
- **Process**: Stealing sync tokens from infected devices
- **Access**: Persistent access to cloud storage accounts
- **Impact**: Data theft, file modification, persistent compromise
- **Protection**: Token encryption, device security, anomaly detection

### Cloud Hopper Attack
- **Type**: Advanced persistent threat targeting managed service providers
- **Method**: Initial compromise of MSPs to reach customer networks
- **Scope**: Supply chain attack affecting multiple organizations
- **Impact**: Data theft, intellectual property loss, extended dwell time
- **Defense**: Supply chain security, vendor assessment, monitoring

### Cloud Cryptojacking
- **Purpose**: Unauthorized cryptocurrency mining using cloud resources
- **Methods**: Compromised containers, malicious images, credential theft
- **Impact**: Resource consumption, increased costs, performance degradation
- **Detection**: Resource monitoring, process analysis, network traffic analysis
- **Prevention**: Access controls, resource limits, security monitoring

### Cloudborne Attack
- **Vector**: Exploiting vulnerabilities in cloud infrastructure
- **Method**: VM escape through hypervisor vulnerabilities
- **Scope**: Cross-tenant attacks, infrastructure compromise
- **Impact**: Data breaches, service disruption, widespread compromise
- **Mitigation**: Hypervisor hardening, isolation controls, patch management

### Instance Metadata Service (IMDS) Attack
- **Target**: Cloud instance metadata services (AWS, Azure, GCP)
- **Method**: SSRF attacks to access metadata endpoints
- **Information**: IAM credentials, security keys, instance configuration
- **Impact**: Credential theft, privilege escalation, lateral movement
- **Protection**: Metadata service hardening, network controls, monitoring

### Cloud Provider DoS (CPDoS) / CDN Cache Poisoning Attack
- **Method**: Cache poisoning attacks against CDN and cloud caching services
- **Technique**: HTTP header manipulation, cache key confusion
- **Impact**: Service denial, content manipulation, cache pollution
- **Scope**: Web applications using CDN services
- **Defense**: Cache configuration, request validation, monitoring

### Cloud Snooper Attack
- **Type**: Virtual machine side-channel attack in cloud environments
- **Method**: Exploiting shared CPU caches and memory systems
- **Target**: Co-located virtual machines on same physical host
- **Information**: Cryptographic keys, sensitive data, process information
- **Mitigation**: Dedicated instances, hardware isolation, secure coding

### Golden SAML Attack
- **Method**: Forging SAML authentication tokens using compromised certificates
- **Process**: Stealing SAML signing certificates from identity providers
- **Impact**: Authentication bypass, persistent access, lateral movement
- **Scope**: Organizations using SAML-based SSO
- **Defense**: Certificate security, monitoring, anomaly detection

### Living Off the Cloud Attack
- **Technique**: Using legitimate cloud services for malicious purposes
- **Methods**: Abusing cloud storage, compute services, APIs
- **Purpose**: Command and control, data exfiltration, persistence
- **Detection**: Behavioral analysis, anomaly detection, traffic monitoring
- **Prevention**: Access controls, usage monitoring, security policies

### Other Cloud Attacks

#### Session Hijacking Using XSS
- **Method**: Cross-site scripting to steal session tokens
- **Context**: Web applications hosted in cloud environments
- **Impact**: Account takeover, unauthorized access, data theft
- **Prevention**: Input validation, CSP headers, secure coding

#### DNS Attacks
- **Types**: DNS poisoning, domain hijacking, subdomain takeover
- **Context**: Cloud DNS services and domain management
- **Impact**: Traffic redirection, phishing, service disruption
- **Protection**: DNSSEC, domain monitoring, DNS security services

#### SQL Injection
- **Target**: Cloud-hosted databases and web applications
- **Method**: Injecting malicious SQL code through input fields
- **Impact**: Data theft, database compromise, privilege escalation
- **Prevention**: Parameterized queries, input validation, WAF

#### Cryptanalysis Attack
- **Purpose**: Breaking cryptographic implementations in cloud services
- **Methods**: Weak key attacks, algorithm flaws, implementation bugs
- **Impact**: Data decryption, authentication bypass, integrity compromise
- **Defense**: Strong encryption, proper implementation, key management

#### Man-in-the-Browser (MITB) Attack
- **Method**: Malware intercepting browser communications with cloud services
- **Process**: Real-time transaction manipulation and data theft
- **Impact**: Financial fraud, data theft, unauthorized actions
- **Protection**: Endpoint security, transaction verification, monitoring

---

## Key CEH v13 Exam Points

### Critical Concepts
1. **OWASP Frameworks**: Master the top 10 risks for cloud, Kubernetes, and serverless
2. **Shared Responsibility**: Understand security responsibilities across different cloud models
3. **Container Security**: Know common vulnerabilities in images, runtime, and orchestration
4. **Cloud Attack Vectors**: Recognize various attack methods and their indicators
5. **Kubernetes Threats**: Understand control plane, node, and workload vulnerabilities
6. **Serverless Risks**: Know unique security challenges in serverless computing
7. **Multi-tenancy Issues**: Understand isolation failures and cross-tenant attacks

### Exam Focus Areas
* **OWASP Top 10**: Detailed knowledge of cloud, Kubernetes, and serverless security risks
* **Container Vulnerabilities**: Image security, runtime threats, registry attacks
* **Cloud Attack Types**: MITC, IMDS, CPDoS, cryptojacking, and advanced persistent threats
* **Kubernetes Security**: RBAC misconfigurations, network policies, admission controllers
* **Serverless Threats**: Injection flaws, over-privileged functions, economic DoS
* **Side Channel Attacks**: Cross-VM breaches, cache attacks, timing attacks
* **Supply Chain Security**: Image tampering, malicious dependencies, registry compromise

### Practical Skills
* Identify OWASP top 10 cloud security risks in given scenarios
* Recognize indicators of container and Kubernetes vulnerabilities
* Analyze serverless function configurations for security flaws
* Distinguish between different cloud attack methodologies
* Evaluate cloud security posture against OWASP frameworks
* Understand the impact and mitigation of various cloud threats
* Assess shared responsibility implications for security incidents
