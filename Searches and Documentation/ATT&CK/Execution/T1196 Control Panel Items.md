```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="control.exe" AND CommandLine="*.cpl*"
| table _time Image, CommandLine, process_name, User, host

```