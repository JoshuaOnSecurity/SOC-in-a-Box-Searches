```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="At.exe" OR process_name="schtasks.exe" 
| table _time Image, CommandLine, process_name, User, host
```