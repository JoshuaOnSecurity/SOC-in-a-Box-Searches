```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="sdbinst.exe"
| table _time Image, CommandLine, ParentImage, User, host
```