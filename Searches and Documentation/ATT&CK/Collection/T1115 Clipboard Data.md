source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="clip.exe") 
| table _time Image, CommandLine, process_name, User, host