```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="cmstp.exe"
| table _time Image, CommandLine, ParentImage, User, host
```