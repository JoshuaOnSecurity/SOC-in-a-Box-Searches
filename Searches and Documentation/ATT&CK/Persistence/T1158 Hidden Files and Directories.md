```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="attrib.exe" 
| table _time Image, CommandLine, process_name, User, host
```