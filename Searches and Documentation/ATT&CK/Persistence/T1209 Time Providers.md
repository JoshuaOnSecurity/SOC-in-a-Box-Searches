```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
TargetObject="*\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\*"
| table _time Image, CommandLine, ParentImage, User, host


```