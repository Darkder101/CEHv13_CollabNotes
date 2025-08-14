# About Enumeration

Enumeration is the process of actively gathering information about a target system or network to discover details that can help in identifying potential attack vectors.  
It goes one step beyond scanning by establishing active connections with the target and extracting information.

---

## 🔹 Key Points about Enumeration
- It is an **active information gathering phase** (unlike passive reconnaissance).  
- Helps attackers map out system details such as users, shares, services, and network resources.  
- In penetration testing, it helps simulate real-world attacker behavior.  
- Enumeration is crucial for identifying **entry points** for exploitation.  

---

## 🔹 Common Targets for Enumeration
- Network services and ports  
- User accounts  
- Shares and directories  
- Running processes and applications  
- Enumeration allows attacker to collect following information  
  - Network Resources  
  - Network shares  
  - Routing Tables  
  - Audit and Service settings  
  - FQDN details  
  - Machine names  
  - Users and groups  
  - Applications and banners  

- Some Services and TCP/UDP ports that can be enumerated are:

| Services                                              | TCP/UDP PORTS |
|-------------------------------------------------------|----------------|
| DNS Server                                            | 53             |
| RPC Endpoint Mapper                                   | 135            |
| NetBIOS Name Service                                  | 137            |
| NetBIOS Session Service                               | 139            |
| Server Message Block                                  | 445            |
| Simple Network Management Protocol                    | 161            |
| Lightweight Directory Access Protocol                 | 389            |
| Network File System                                   | 2049           |
| Simple mail Transfer Protocol                         | 25             |
| Secure Shell / Secure File Transfer Protocol          | 22             |
| Simple Network Management Protocol Trap               | 162            |
| Internet Security Association and Key Management Protocol | 500        |
| Global Catalog Service                                | 3268           |
| File Transfer Protocol                                | 20/21          |
| Telnet Protocol                                       | 23             |
| Trivial File Transfer Protocol                        | 69             |
| Border Gateway Protocol                               | 179            |


---

## 🔹 Enumeration in CEH
- Exam tests knowledge of different techniques and tools used in enumeration.  
- Each technique (e.g., NetBIOS, SNMP, LDAP, DNS, etc.) will be covered in separate detailed markdown files.  

---

✅ This file is just a **high-level overview**. Each enumeration technique will be documented individually in separate `.md` files.
