Input Source: Sysmon
Discovers untrusted applications editing sysmon registry.
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(event_id=12 OR event_id=13 OR event_id=14) (registry_key_path="HKLM\\System\\CurrentControlSet\\Services\\SysmonDrv\\*" 
OR registry_key_path="HKLM\\System\\CurrentControlSet\\Services\\Sysmon\\*" 
OR registry_key_path="HKLM\\System\\CurrentControlSet\\Services\\Sysmon64\\*") 
"process_name"!="Sysmon64.exe" "process_name"!="Sysmon.exe"
| table _time, host, Image, ProcessGuid, TargetObject, EventType
```
Input Source: Sysmon
Discovers if a sysmon state changes. Could indicate malicous activity. 
```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="fltmc.exe" AND CommandLine="*unload*"
| table _time OriginalFileName, CommandLine, user, host
```
