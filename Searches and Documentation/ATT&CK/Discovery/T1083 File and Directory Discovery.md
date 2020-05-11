```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="tree.com"
| table _time Image, CommandLine, process_name, User, host
```