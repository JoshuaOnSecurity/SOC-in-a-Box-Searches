source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(CommandLine="*tscon*rdp*")
| table _time Image, CommandLine, process_name, User, host