```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="control.exe" AND CommandLine="*.cpl*"
| table _time Image, CommandLine, ParentImage, User, host
```