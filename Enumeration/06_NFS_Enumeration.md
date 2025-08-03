## NFS Enumeration

- **NFS Enumeration Enables attackers to identify:**
  - Exported Directories
  - List of Clients
  - Shared Data

- **NFS Enumeration Commands:**
  - `rpcinfo -p <Target IP Address>`
  - `showmount -e <Target IP Address>`

- **NFS Enumeration Tools:**
  - RPCScan
  - SuperEnum

- **Countermeasures:**
  - Implement Proper Permission
  - Implement Firewall rules to block NFS port
  - Log the requests
  - Proper configurations of `/etc/smb.conf`, `/etc/exports`, `/etc/hosts.allow`
