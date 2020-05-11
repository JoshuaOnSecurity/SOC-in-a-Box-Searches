```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="sc.exe" OR process_name="powershell.exe" OR process_name="cmd.exe") 
AND (CommandLine="*sc*config*binpath*")
| table _time Image, CommandLine, process_name, User, host
```