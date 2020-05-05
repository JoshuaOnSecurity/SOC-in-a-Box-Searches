```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="cscript.exe" OR CommandLine="*pubprn.vbs*"
| table _time Image, CommandLine, ParentImage, User, host
```