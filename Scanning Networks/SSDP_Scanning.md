# SSDP Scanning

## Definition

SSDP (Simple Service Discovery Protocol) scanning is used to discover UPnP-enabled devices on a network, often using UDP port 1900.

## How SSDP Scan Works

### Basic Process:
1. Send M-SEARCH SSDP requests to multicast address 239.255.255.250:1900.
2. Devices respond with service descriptions.

## Tools and Commands

### Example with Nmap
```bash
nmap --script=upnp-info -p 1900 target_ip
```

## Advantages
- Quickly identifies UPnP devices.
- Can reveal device and service details.

## Limitations
- Limited to UPnP-enabled hosts.
- May be filtered by routers/firewalls.

## Detection and Response

### Detection Methods:
- Monitoring for UDP M-SEARCH messages.

## CEH Exam Focus Points
- SSDP uses UDP/1900 and multicast address.
- Useful for IoT and home network reconnaissance.
