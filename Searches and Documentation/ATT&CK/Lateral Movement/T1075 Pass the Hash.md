source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(CommandLine="*sekurlsa*")
| table _time Image, CommandLine, process_name, User, host
