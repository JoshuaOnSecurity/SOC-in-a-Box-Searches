```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(OriginalFileName="sc.exe" OR OriginalFileName="powershell.exe" OR OriginalFileName="cmd.exe") 
AND (CommandLine="*sc*config*binpath*")
| table _time Image, CommandLine, ParentImage, User, host
```