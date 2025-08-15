# Web Server Hacking

## Table of Contents
1. [Web Server Fundamentals](#web-server-fundamentals)
2. [Web Server Operations](#web-server-operations)
3. [Components of Web Servers](#components-of-web-servers)
4. [Web Security Issues](#web-security-issues)
5. [Apache Web Server](#apache-web-server)
6. [IIS Web Server](#iis-web-server)
7. [Nginx Web Server](#nginx-web-server)
8. [Other Popular Web Servers](#other-popular-web-servers)
9. [Web Server Attack Vectors](#web-server-attack-vectors)
10. [Web Server Security Hardening](#web-server-security-hardening)

## Web Server Fundamentals

### What is a Web Server?
- A web server is a system that delivers web content to users via HTTP/HTTPS protocols
- Acts as an intermediary between client requests and web applications
- Processes incoming requests and serves static/dynamic content
- Handles multiple concurrent connections and sessions

### Key Functions
- **Request Processing**: Parse HTTP requests and route to appropriate handlers
- **Content Delivery**: Serve static files (HTML, CSS, JS, images) and dynamic content
- **Security Management**: Authentication, authorization, and access control
- **Load Management**: Handle concurrent connections and resource allocation
- **Logging**: Record access logs, error logs, and security events

## Web Server Operations

### HTTP Protocol Handling
- **HTTP Methods**: GET, POST, PUT, DELETE, HEAD, OPTIONS, TRACE, PATCH
- **Status Codes**: 1xx (Informational), 2xx (Success), 3xx (Redirection), 4xx (Client Error), 5xx (Server Error)
- **Headers Management**: Request/response headers processing
- **Session Management**: Cookie handling, session tokens, state management

### Connection Management
- **Persistent Connections**: Keep-alive connections for performance
- **Connection Pooling**: Reuse connections to reduce overhead
- **Timeout Handling**: Connection, read, and write timeouts
- **SSL/TLS Termination**: HTTPS encryption/decryption

### Content Processing
- **Static Content**: Direct file serving from filesystem
- **Dynamic Content**: CGI, FastCGI, mod_php, WSGI processing
- **URL Rewriting**: Modification of URLs for SEO and routing
- **Virtual Hosting**: Multiple domains on single server

## Components of Web Servers

### Core Components
1. **HTTP Engine**: Core protocol implementation
2. **Request Parser**: Analyze incoming HTTP requests
3. **Response Generator**: Format and send HTTP responses
4. **File Handler**: Manage static file serving
5. **Module System**: Plugin architecture for extending functionality

### Supporting Components
- **Configuration Manager**: Parse and apply server configurations
- **Authentication Module**: User verification and access control
- **Logging System**: Access logs, error logs, security logs
- **Cache Manager**: In-memory and disk-based caching
- **Compression Engine**: Gzip, Brotli content compression

### Security Components
- **Access Control Lists (ACL)**: Directory and file permissions
- **Rate Limiting**: Request throttling and DoS protection
- **Input Validation**: Sanitize user inputs
- **SSL/TLS Handler**: Certificate management and encryption
- **Security Headers**: HSTS, CSP, X-Frame-Options implementation

## Web Security Issues

### Common Vulnerabilities
1. **Directory Traversal**: Access to files outside web root
2. **Information Disclosure**: Exposure of sensitive server information
3. **Default Configurations**: Weak default settings and accounts
4. **Unpatched Software**: Known vulnerabilities in server software
5. **Misconfiguration**: Improper security settings

### Attack Vectors
- **Server-Side Request Forgery (SSRF)**: Force server to make unintended requests
- **HTTP Response Splitting**: Injection of malicious headers
- **Web Cache Poisoning**: Manipulation of cached content
- **HTTP Parameter Pollution**: Multiple parameters with same name
- **Slowloris Attacks**: Slow HTTP DoS attacks

### Security Misconfigurations
- **Excessive Permissions**: Overly permissive file/directory access
- **Debug Information**: Development settings in production
- **Verbose Error Messages**: Information leakage through errors
- **Unnecessary Services**: Running unused modules and services
- **Weak Authentication**: Poor password policies and account management

## Apache Web Server
<img width="901" height="233" alt="image" src="https://github.com/user-attachments/assets/e612f178-b902-486d-a2c7-191b75f6dac2" />

### Architecture Overview
- **Multi-Processing Modules (MPM)**: prefork, worker, event
- **Modular Design**: Dynamic module loading system
- **Virtual Host Support**: Name-based and IP-based virtual hosting
- **Configuration Hierarchy**: Global, virtual host, directory levels

### Core Modules
- **mod_ssl**: SSL/TLS encryption support
- **mod_rewrite**: URL rewriting and redirection
- **mod_auth_basic**: Basic HTTP authentication
- **mod_dir**: Directory indexing and default files
- **mod_mime**: MIME type handling
- **mod_log_config**: Customizable logging

### Apache HTTP Server (HTTPD) Vulnerabilities
<img width="1772" height="747" alt="image" src="https://github.com/user-attachments/assets/cf8f0b3a-240d-4b05-bd61-48dccb0cf307" />

#### Historical Vulnerabilities
- **CVE-2021-44790**: mod_lua Request Smuggling
- **CVE-2021-44224**: mod_proxy SSRF vulnerability
- **CVE-2021-42013**: Path traversal and RCE in mod_cgi
- **CVE-2021-42012**: Null pointer dereference in mod_proxy_uwsgi
- **CVE-2021-41773**: Path traversal vulnerability

#### Common Security Issues
- **Default Document Root**: /var/www/html exposure
- **Server-Status Module**: Information disclosure via /server-status
- **Server-Info Module**: Configuration disclosure via /server-info
- **htaccess Vulnerabilities**: Misconfigured access control files
- **CGI Script Vulnerabilities**: Insecure CGI implementations

#### Configuration Vulnerabilities
```apache
# Dangerous configurations
ServerTokens Full          # Reveals server version
ServerSignature On         # Shows server info in error pages
AllowOverride All         # Allows .htaccess overrides everywhere
Options Indexes           # Directory browsing enabled
```

### Apache Security Hardening
- **Hide Version Information**: ServerTokens Prod, ServerSignature Off
- **Disable Unnecessary Modules**: Remove unused modules
- **Secure Directory Permissions**: Proper file/directory permissions
- **Implement Access Controls**: Restrict access to sensitive directories
- **Enable Security Headers**: HSTS, CSP, X-Frame-Options

## IIS Web Server
<img width="897" height="482" alt="image" src="https://github.com/user-attachments/assets/54b4f4b5-5a29-43fe-ab04-e4d2e76739f2" />

### Architecture Overview
- **Windows Integration**: Deep OS integration with Windows
- **Application Pools**: Isolated execution environments
- **ISAPI Extensions**: Dynamic content processing
- **HTTP.sys Kernel Driver**: Low-level HTTP processing

### IIS Components
- **World Wide Web Publishing Service (W3SVC)**: Core web service
- **IIS Manager**: Graphical management interface
- **Application Pool Worker Process (w3wp.exe)**: Request processing
- **HTTP.sys**: Kernel-mode HTTP listener
- **WAS (Windows Activation Service)**: Process lifecycle management

### IIS Vulnerabilities
<img width="1603" height="667" alt="image" src="https://github.com/user-attachments/assets/f7450584-15da-4a59-b6de-bec341555ebb" />

#### Common IIS Attacks
- **IIS Shortname Scanning**: 8.3 filename enumeration
- **WebDAV Vulnerabilities**: Unauthorized file access and modification
- **ASP.NET ViewState Attacks**: Deserialization vulnerabilities
- **IIS Tilde Enumeration**: Short filename disclosure
- **NTLM Authentication Bypass**: Authentication mechanism flaws

#### Historical Vulnerabilities
- **CVE-2021-31207**: HTTP Protocol Stack RCE
- **CVE-2021-24092**: IIS HTTP/2 Implementation Vulnerability
- **CVE-2020-0618**: ASP.NET Core Information Disclosure
- **CVE-2019-0604**: SharePoint RCE vulnerability
- **CVE-2017-7269**: Buffer overflow in WebDAV service

#### Configuration Issues
- **Anonymous Authentication**: Overly permissive access
- **Directory Browsing**: Enabled directory listing
- **Detailed Error Messages**: Information disclosure
- **Weak NTFS Permissions**: File system access issues
- **Default Website Configuration**: Insecure default settings

### IIS Security Features
- **Request Filtering**: Block malicious requests
- **URL Authorization**: Fine-grained access control
- **SSL/TLS Configuration**: Certificate management
- **IP and Domain Restrictions**: Network-level access control
- **Failed Request Tracing**: Security event logging

## Nginx Web Server
<img width="703" height="458" alt="image" src="https://github.com/user-attachments/assets/1eda1a0f-abec-4f6e-b4e4-9dfacdc9687d" />

### Architecture Overview
- **Event-Driven Architecture**: Asynchronous, non-blocking I/O
- **Master-Worker Process Model**: Single master, multiple worker processes
- **Reverse Proxy Capabilities**: Load balancing and caching
- **Modular Design**: Compile-time module selection

### Nginx Core Features
- **HTTP Server**: Static and dynamic content serving
- **Reverse Proxy**: Backend application integration
- **Load Balancer**: Multiple load balancing algorithms
- **SSL Termination**: HTTPS encryption handling
- **Rate Limiting**: Request throttling and DoS protection

### Nginx Vulnerabilities
<img width="1577" height="648" alt="image" src="https://github.com/user-attachments/assets/84f12ba3-6481-4ad7-9d75-db3c456ef786" />

#### Security Issues
- **CVE-2021-23017**: Resolver Off-by-One Buffer Overflow
- **CVE-2019-20372**: HTTP Request Smuggling
- **CVE-2018-16845**: Excessive Memory Consumption in mp4 module
- **CVE-2017-7529**: Integer overflow in range filter
- **CVE-2016-0742**: Use-after-free in resolver

#### Common Misconfigurations
- **Alias Traversal**: Improper alias directive usage
- **Merge Slashes**: Path confusion vulnerabilities
- **Missing Root Context**: Default server vulnerabilities
- **Unsafe Variable Usage**: $uri vs $request_uri confusion
- **CRLF Injection**: Header injection vulnerabilities

### Nginx Security Hardening
```nginx
# Security-focused configuration
server_tokens off;                    # Hide version information
add_header X-Frame-Options DENY;     # Prevent clickjacking
add_header X-Content-Type-Options nosniff;  # Prevent MIME sniffing
client_max_body_size 10M;           # Limit request body size
limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;  # Rate limiting
```

## Other Popular Web Servers

### Apache Tomcat
- **Java Servlet Container**: JSP and servlet processing
- **Manager Application**: Web-based administration interface
- **Common Vulnerabilities**: Default credentials, manager app exposure
- **Security Focus**: Disable manager apps, secure connectors

### LiteSpeed Web Server
- **High Performance**: Event-driven architecture
- **Apache Compatibility**: .htaccess support
- **Built-in Security**: Anti-DDoS protection, mod_security compatible
- **PHP Optimization**: LiteSpeed SAPI for improved performance

### Cloudflare (Edge Server)
- **CDN Integration**: Global content delivery network
- **DDoS Protection**: Layer 3/4 and Layer 7 protection
- **Web Application Firewall**: Built-in security rules
- **SSL/TLS Management**: Automated certificate provisioning

### OpenResty
- **Nginx + Lua**: Extensible web platform
- **Dynamic Content**: Lua scripting for web applications
- **High Concurrency**: Event-driven processing
- **API Gateway**: RESTful API management capabilities

### Microsoft Exchange Web Services
- **Email Web Interface**: Outlook Web App (OWA)
- **ActiveSync**: Mobile device synchronization
- **Common Attacks**: Credential spraying, Exchange vulnerabilities
- **Security Considerations**: Multi-factor authentication, IP restrictions

### Node.js HTTP Server
- **JavaScript Runtime**: Server-side JavaScript execution
- **Event Loop**: Non-blocking I/O operations
- **NPM Dependencies**: Third-party module vulnerabilities
- **Security Challenges**: Prototype pollution, dependency vulnerabilities

## Web Server Attack Vectors

### Information Gathering
- **Banner Grabbing**: Server version and software identification
- **Directory Enumeration**: Discover hidden directories and files
- **Technology Stack Fingerprinting**: Identify underlying technologies
- **Error Message Analysis**: Extract sensitive information from errors

### Authentication Attacks
- **Brute Force**: Password guessing attacks
- **Dictionary Attacks**: Common password attempts
- **Credential Stuffing**: Reused password exploitation
- **Session Hijacking**: Steal or manipulate session tokens

### Directory and File Attacks
- **Directory Traversal**: Access files outside web root
- **Local File Inclusion (LFI)**: Include local files in web pages
- **Remote File Inclusion (RFI)**: Include remote malicious files
- **File Upload Attacks**: Upload malicious files to server

### Denial of Service (DoS)
- **HTTP Flood**: Overwhelming server with HTTP requests
- **Slowloris**: Slow connection exhaustion attack
- **Slow HTTP POST**: Gradual data transmission attack
- **Resource Exhaustion**: Memory, CPU, or disk space consumption

### Web Server Specific Attacks
- **HTTP Response Splitting**: Header injection attacks
- **HTTP Request Smuggling**: Request interpretation inconsistencies
- **Server-Side Request Forgery (SSRF)**: Force server-side requests
- **Web Cache Deception**: Manipulate cache behavior

## Web Server Security Hardening

### General Hardening Principles
1. **Principle of Least Privilege**: Minimal necessary permissions
2. **Defense in Depth**: Multiple security layers
3. **Regular Updates**: Keep software current with patches
4. **Security Monitoring**: Continuous logging and alerting
5. **Configuration Management**: Standardized secure configurations

### Common Hardening Steps
- **Remove Default Accounts**: Delete or disable default users
- **Disable Unnecessary Services**: Stop unused modules and services
- **Implement Access Controls**: Restrict directory and file access
- **Configure Security Headers**: HSTS, CSP, CSRF protection
- **Enable Logging**: Comprehensive audit trails
- **SSL/TLS Configuration**: Strong encryption protocols
- **Input Validation**: Sanitize all user inputs
- **Error Handling**: Generic error messages without information disclosure

### Monitoring and Incident Response
- **Real-time Monitoring**: Continuous security event detection
- **Log Analysis**: Regular review of access and error logs
- **Intrusion Detection**: Automated threat detection systems
- **Incident Response Plan**: Documented response procedures
- **Backup and Recovery**: Regular backups and tested restoration

### Compliance Considerations
- **PCI DSS**: Payment card industry standards
- **GDPR**: Data protection regulations
- **OWASP Guidelines**: Web application security standards
- **Industry Standards**: Sector-specific security requirements

---

## Key Exam Points for CEH v13

### Critical Topics to Remember
1. **Default Configurations**: Know common default settings and vulnerabilities
2. **Version Disclosure**: Methods to hide server version information
3. **Directory Traversal**: Understanding path manipulation attacks
4. **Authentication Bypass**: Common techniques and preventions
5. **SSL/TLS Issues**: Certificate vulnerabilities and misconfigurations
6. **Log Analysis**: Identifying attack patterns in web server logs
7. **Hardening Techniques**: Essential security configurations for each server type

### Tools and Techniques
- **Nmap**: Service detection and vulnerability scanning
- **Nikto**: Web server vulnerability scanner
- **Burp Suite**: Web application security testing
- **OWASP ZAP**: Security testing proxy
- **Metasploit**: Exploitation framework modules
- **Gobuster/DirBuster**: Directory and file enumeration

### Common Attack Signatures
- Recognize attack patterns in log files
- Understand HTTP status codes and their security implications
- Identify information disclosure through error messages
- Know common exploit techniques for each web server type
