```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="regsvcs.exe" OR OriginalFileName="regasm.exe"
| table _time Image, CommandLine, ParentImage, User, host
```