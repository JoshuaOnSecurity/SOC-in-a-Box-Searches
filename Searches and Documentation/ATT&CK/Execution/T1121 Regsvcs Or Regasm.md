```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="regsvcs.exe" OR process_name="regasm.exe" OR process_name="csc.exe"
| table _time Image, CommandLine, process_name, User, host
```