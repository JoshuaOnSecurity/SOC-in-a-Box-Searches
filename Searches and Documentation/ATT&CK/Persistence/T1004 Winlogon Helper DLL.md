```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\*"
OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*"
OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\*"
| table _time Image, TargetObject, host
```