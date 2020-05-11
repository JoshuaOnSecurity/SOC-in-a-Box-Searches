source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="reg.exe" AND CommandLine="*query*pass*")
| table _time Image, CommandLine, process_name, User, host
