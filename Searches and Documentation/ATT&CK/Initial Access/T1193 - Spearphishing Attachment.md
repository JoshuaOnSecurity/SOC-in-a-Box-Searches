```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
ParentImage="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE" 
CommandLine="*.hta*" OR CommandLine="*.doc*" 
| table _time Image, CommandLine, ParentImage, User, host
```