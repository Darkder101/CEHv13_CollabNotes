## NetBIOS Enumeration
- NetBIOS Name is 16 Character string used to identify the network device  
- NetBIOS Enumeration obtains following information  
  - List of Computers belong to that domain  
  - List of shares on individual hosts in network  
  - Policies and Passwords  

- NetBIOS Enumeration Tools:  
  - NetBIOS Enumerator  
  - Nmap  
    - `nmap -sV -v --script nbtstat.nse <target IP address>`  
  - Global Network Inventory  
  - Advanced IP Scanner  
  - Hyena  
  - Nsauditor  

- Enumerating User Accounts Using (PSTools Suite):  
  - PsExec, PsFile, PsGetSid, PsKill, Psinfo, PsList, Psloglist, PsloggedOn  

- Enumerating Shared Resources Using Net View:  
  - `net view \\<ComputerName>`  
  - `net view \\<ComputerName>\\all`  
  - `net view /domain`  
