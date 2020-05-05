```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
ParentImage="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE" 
AND Image="C:\\Program Files\\Mozilla Firefox\\firefox.exe" 
AND CommandLine="*www.*"
| table _time Image, CommandLine, ParentImage, User, host
```