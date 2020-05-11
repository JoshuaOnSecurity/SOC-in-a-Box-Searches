```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="net.exe" AND CommandLine="*share*" AND CommandLine="*del*")
| table _time Image, CommandLine, process_name, User, host
```