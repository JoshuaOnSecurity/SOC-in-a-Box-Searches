```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="regsvr32.exe" OR CommandLine="*regsvr32.exe*"
| table _time Image, CommandLine, process_name, User, host
```