```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="attrib.exe" 
| table _time Image, CommandLine, ParentImage, User, host
```