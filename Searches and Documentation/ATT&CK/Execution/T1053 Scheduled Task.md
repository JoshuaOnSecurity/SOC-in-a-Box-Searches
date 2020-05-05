```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="At.exe" OR OriginalFileName="schtasks.exe" 
| table _time Image, CommandLine, ParentImage, User, host
```