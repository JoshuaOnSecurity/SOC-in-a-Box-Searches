```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
TargetObject="*\\ms-settings\\shell\\open\\command\\*"
OR TargetObject="*\\mscfile\\shell\\open\\command\\*"
OR TargetObject="*Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe*"
OR TargetObject="*shell\\runas\\command\\isolatedCommand*"
| table _time Image, TargetObject, host
```
