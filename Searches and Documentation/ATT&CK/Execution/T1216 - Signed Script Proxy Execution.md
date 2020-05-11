```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="cscript.exe" OR CommandLine="*pubprn.vbs*"
| table _time Image, CommandLine, process_name, User, host
```