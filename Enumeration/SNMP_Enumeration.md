## SNMP Enumeration
- Simple Network Management Protocol  
- SNMP Enumeration obtains following information:  
  - Hosts  
  - Routers  
  - Devices  
  - Shares  
  - ARP tables / Routing tables  

- SNMP Enumeration tools:  
  - SnmpWalk:  
    - `snmpwalk -v1 -c Public <Target IP address>`  
  - Nmap:  
    - `nmap -sU -p 161 --script=snmp-process <Target IP address>`  
  - Snmp-check  
  - SoftPerfect Network Scanner  
  - Network Performance Monitor  
  - OpUtils  
  - PRTG Network Monitor  
  - Engineers Toolset  

- COUNTERMEASURES:  
  - Remove SNMP agent or turn off SNMP service  
  - If can't turn it off, change the default community string names  
  - Upgrade to SNMPv3  
