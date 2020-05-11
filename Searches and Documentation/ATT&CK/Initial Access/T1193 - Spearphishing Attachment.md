```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE" 
CommandLine="*.hta*" OR CommandLine="*.doc*" 
| table _time Image, CommandLine, process_name, User, host
```