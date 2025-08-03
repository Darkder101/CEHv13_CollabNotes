## DNS Enumeration

- **DNS is Domain Name Server**

- **DNS Enumeration using DNS Zone Transfer:**
  - Can obtain DNS server names, hostnames, machine names, usernames, IP addresses, aliases
  - If DNS Zone Transfer is enabled, it will provide DNS information; otherwise, it will return an error indicating failure or refusal
  - Tools used: DNSRecon, `nslookup`, `dig`
  - **`dig` Commands:**
    - `dig ns <Target Domain>`
    - `dig @<domain name of the server> <Target Domain> axfr`
  - **`nslookup` Commands:**
    - `nslookup`
    - `set querytype=soa`
    - `<target domain>`
    - `/ls -d <domain name of server>`
  - Tool: DNSRecon

- **DNS Enumeration using DNS Cache Snooping:**
  - Attacker queries the DNS server for specific cached DNS records
  - `dig @<IP of DNS server> <Target domain> A +norecurse` or `+recurse`
  - `Status: NOERROR` indicates query was accepted but site is not cached
  - High TTL value indicates the record is not in the cache

- **DNS Enumeration using DNSSEC Zone Walking:**
  - Domain Name System Security Extensions
  - Tools for DNSSEC Zone Enumeration:
    - LDNS
    - DNSRecon
    - Nsec3map
    - Nsec3walker
    - DNSwalk
    - DNS Enumeration using OWASP Amass
    - DNS and DNSSEC Enumeration using Nmap

- **Countermeasures:**
  - DNS resolver access should be limited to internal hosts
  - Ensure outbound DNS requests use random source ports
  - Audit DNS zones for vulnerabilities
  - Regularly update and patch nameservers
