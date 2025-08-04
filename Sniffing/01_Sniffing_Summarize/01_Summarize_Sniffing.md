# Network Sniffing Overview

## a. Network Sniffing

- **Definition**: Monitoring and capturing network packets  
- **Purpose**: Intercept traffic for analysis  
- **Uses**:  
  - Legitimate: Troubleshooting  
  - Malicious: Data theft  
- **Key Point**: Works by putting the Network Interface Card (NIC) in **promiscuous mode**

---

## b. How a Sniffer Works

- **Process**: NIC → Promiscuous Mode → Capture All Packets → Analysis  
- **Normal Mode**: Only captures packets intended for the specific MAC address  
- **Promiscuous Mode**: Captures all packets on the network segment  
- **OSI Layer**: Operates at the **Data Link Layer (Layer 2)**

---

## c. Types of Sniffing

- **Passive Sniffing**:
  - Listens only
  - Works on hubs or wireless networks
  - Hard to detect

- **Active Sniffing**:
  - Injects packets into the network
  - Required for switched networks
  - Easier to detect

- **Key Difference**:
  - **Hubs** → Passive sniffing is sufficient  
  - **Switches** → Active sniffing is needed

---

## d. How an Attacker Hacks Network Using Sniffers

- **Steps**:
  1. Reconnaissance
  2. Access the network
  3. Deploy sniffing tools
  4. Capture traffic
  5. Extract sensitive data

- **Targets**:
  - Passwords
  - Session tokens
  - Sensitive communications

- **Common Tools**:
  - Wireshark
  - tcpdump
  - Custom sniffers

---

## e. Protocols Vulnerable to Sniffing

- **Vulnerable Protocols**:
  - HTTP
  - FTP
  - Telnet
  - SMTP
  - POP3
  - SNMP v1/v2

- **Secure Protocols**:
  - HTTPS
  - SFTP
  - SSH
  - SNMP v3

- **Common Ports to Remember**:
  - HTTP: `80`  
  - HTTPS: `443`  
  - SNMP: `161`

---

## f. Sniffing in Data Link Layer

- **Operation Layer**: Data Link Layer (Layer 2)  
- **Captures**:
  - MAC addresses
  - Frame headers
  - Payload data

- **Challenge with Switches**:
  - **CAM tables** limit traffic visibility

---

## g. SPAN Port

- **Purpose**: Mirror traffic to a monitoring port for analysis  
- **Types**:
  - **Local SPAN**
  - **Remote SPAN (RSPAN)**
  - **Encapsulated Remote SPAN (ERSPAN)**

- **Security Considerations**:
  - Read-only access
  - Requires administrative rights
