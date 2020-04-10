```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="tree.com"
| table _time Image, CommandLine, ParentImage, User, host
```