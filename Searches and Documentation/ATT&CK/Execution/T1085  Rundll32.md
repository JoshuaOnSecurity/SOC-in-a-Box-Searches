```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="rundll32.exe"
| table _time Image, CommandLine, ParentImage, User, host
```