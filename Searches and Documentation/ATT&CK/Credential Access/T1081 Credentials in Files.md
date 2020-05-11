source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="findstr.exe" AND CommandLine="*pass*")
OR CommandLine="*unattend.xml*"
| table _time Image, CommandLine, process_name, User, host
