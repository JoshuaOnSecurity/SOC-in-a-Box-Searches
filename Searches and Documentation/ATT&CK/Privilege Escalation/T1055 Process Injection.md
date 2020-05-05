```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="mavinject.exe" OR CommandLine="*/INJECTRUNNING*"
| table _time Image, CommandLine, ParentImage, User, host

```
