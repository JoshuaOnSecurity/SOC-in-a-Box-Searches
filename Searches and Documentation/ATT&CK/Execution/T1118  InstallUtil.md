```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="InstallUtil.exe" 
| table _time Image, CommandLine, ParentImage, User, host
```