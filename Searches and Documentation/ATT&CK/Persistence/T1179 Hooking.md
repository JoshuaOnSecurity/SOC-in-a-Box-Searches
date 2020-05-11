```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="mavinject.exe" OR CommandLine="*/INJECTRUNNING*"
| table _time Image, CommandLine, process_name, User, host
```