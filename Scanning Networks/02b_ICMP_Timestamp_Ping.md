# ICMP Timestamp Ping

## Definition

ICMP Timestamp Ping is an alternative host discovery technique that uses ICMP Timestamp Request messages (Type 13) instead of standard Echo Request messages. This method requests the current time from target hosts, which respond with ICMP Timestamp Reply messages (Type 14) if they support this functionality. It's particularly useful when standard ICMP Echo requests are blocked by firewalls.

## How ICMP Timestamp Ping Works

### Basic Process:
1. **Source Host** sends ICMP Timestamp Request packet (Type 13, Code 0)
2. **Target Host** receives the timestamp request
3. **Target Host** processes request and calculates current time
4. **Target Host** sends ICMP Timestamp Reply (Type 14, Code 0) with time information
5. **Source Host** receives reply, confirming target is alive and may extract timing info

### Packet Structure:
- **IP Header**: Source and destination IP addresses
- **ICMP Header**: Type 13 (Timestamp Request), Code 0, Checksum, Identifier, Sequence Number
- **Timestamp Fields**: Originate Timestamp, Receive Timestamp, Transmit Timestamp
- **Time Format**: Milliseconds since midnight UTC

## ICMP Message Types

| Type | Code | Description |
|------|------|-------------|
| 13   | 0    | Timestamp Request |
| 14   | 0    | Timestamp Reply |

## Tools and Commands

### Nmap ICMP Timestamp Ping
```bash
# ICMP Timestamp ping scan
nmap -PP target_ip

# Timestamp ping for IP range
nmap -sn -PP 192.168.1.0/24

# Combined with other ping types
nmap -sn -PE -PP 192.168.1.1

# Verbose timestamp ping scan
nmap -sn -PP -v 192.168.1.0/24
```

### Hping3 Timestamp Requests
```bash
# Send ICMP timestamp request
hping3 -1 -C 13 target_ip

# Timestamp request with count
hping3 -1 -C 13 -c 3 192.168.1.1

# Timestamp request with interval
hping3 -1 -C 13 -i 2 192.168.1.1
```

### PowerShell Timestamp Check
```powershell
# Test timestamp functionality
Test-NetConnection -ComputerName target_ip -InformationLevel Detailed
```

## Timestamp Information

### Time Format:
- **32-bit Value**: Milliseconds since midnight UTC
- **Originate Time**: When request was sent
- **Receive Time**: When request was received by target
- **Transmit Time**: When reply was sent by target

### Time Calculation:
```
Network Delay = ((Receive Time - Originate Time) + (Current Time - Transmit Time)) / 2
Clock Difference = Receive Time - Originate Time - Network Delay
```

## Advantages

- **Firewall Evasion**: Often bypasses filters that block ICMP Echo
- **Less Common**: Not typically monitored as closely as Echo requests  
- **Additional Information**: Provides timestamp data for network analysis
- **Alternative Method**: Works when standard ping fails
- **Time Synchronization**: Can help identify time synchronization issues
- **Network Diagnostics**: Useful for measuring network delays

## Limitations

- **Limited Support**: Not all systems respond to timestamp requests
- **Disabled by Default**: Many modern systems disable timestamp responses
- **Security Concerns**: Timestamp info can reveal system information
- **Firewall Blocking**: Advanced firewalls may block timestamp requests too
- **False Negatives**: Host may be alive but not supporting timestamps
- **OS Dependent**: Response varies significantly between operating systems

## System Response Behaviors

### Windows Systems:
- **Older Versions**: Often respond to timestamp requests
- **Windows 10/11**: Timestamp responses typically disabled by default
- **Server Versions**: May have timestamp responses enabled

### Linux/Unix Systems:
- **Default Behavior**: Usually respond to timestamp requests
- **Configuration**: Can be disabled via kernel parameters
- **Firewall Rules**: May be blocked by iptables/firewall rules

### Network Devices:
- **Routers**: Often respond to timestamp requests
- **Switches**: Response varies by manufacturer and configuration
- **Firewalls**: Usually filter or respond depending on policy

## Security Implications

### Information Disclosure:
- **System Time**: Reveals current system time
- **Time Zone**: May indicate geographical location
- **Clock Skew**: Can help with OS fingerprinting
- **Network Topology**: Timestamp analysis reveals network delays

### For Defenders:
- **Disable Timestamp**: Consider disabling ICMP timestamp responses
- **Monitor Traffic**: Watch for unusual timestamp request patterns
- **Information Leakage**: Assess what timing information reveals
- **Policy Implementation**: Develop ICMP filtering policies

### For Penetration Testers:
- **Alternative Discovery**: Use when standard ping fails
- **Information Gathering**: Extract timing information for analysis
- **Firewall Testing**: Test ICMP filtering effectiveness
- **OS Fingerprinting**: Use timestamp behavior for OS identification

## Detection and Evasion

### Detection Methods:
- **Network Monitoring**: IDS signatures for timestamp requests
- **Traffic Analysis**: Unusual patterns of Type 13 ICMP packets
- **Log Analysis**: System logs showing timestamp request processing
- **Anomaly Detection**: Unexpected timestamp request volumes

### Evasion Techniques:
- **Mixed Scanning**: Combine with other discovery methods
- **Timing Variation**: Random intervals between requests
- **Source Spoofing**: Use different source addresses (where possible)
- **Fragmentation**: Fragment timestamp packets
- **Decoy Traffic**: Mix with legitimate network activity

## Practical Examples

### Successful Timestamp Response:
```
ICMP Timestamp Request to 192.168.1.1
Response received: Type 14 (Timestamp Reply)
Originate: 12:34:56.789
Receive:   12:34:56.791
Transmit:  12:34:56.792
Round-trip time: 3ms
```

### No Response (Filtered):
```
ICMP Timestamp Request to 192.168.1.1
No response received (may be filtered or unsupported)
```

### System Doesn't Support:
```
ICMP Timestamp Request to 192.168.1.1  
ICMP Destination Unreachable (Port Unreachable)
```

## CEH Exam Focus Points

- Understand ICMP Timestamp message types (13 and 14)
- Know when to use timestamp ping vs. echo ping
- Recognize systems that support vs. block timestamp requests
- Understand information disclosure risks of timestamp responses
- Be familiar with Nmap -PP option for timestamp ping
- Know how timestamp ping can bypass certain firewall rules
- Understand timestamp format and time calculation methods
---
