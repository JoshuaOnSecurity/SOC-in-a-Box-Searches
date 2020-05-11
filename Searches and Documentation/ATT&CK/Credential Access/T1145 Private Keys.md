source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="dir.exe" OR process_name="findstr.exe" AND CommandLine="*.key*")
| table _time Image, CommandLine, process_name, User, host