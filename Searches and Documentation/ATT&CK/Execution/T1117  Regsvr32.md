```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="regsvr32.exe" OR CommandLine="*regsvr32.exe*"
| table _time Image, CommandLine, ParentImage, User, host
```