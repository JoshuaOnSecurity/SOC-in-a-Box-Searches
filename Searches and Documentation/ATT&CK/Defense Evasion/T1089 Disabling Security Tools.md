Input Source: Sysmon

Discovers if a sysmon state changes. Could indicate malicous activity. 
```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="fltmc.exe" AND CommandLine="*unload*"
| table _time process_name, CommandLine, user, host
```
