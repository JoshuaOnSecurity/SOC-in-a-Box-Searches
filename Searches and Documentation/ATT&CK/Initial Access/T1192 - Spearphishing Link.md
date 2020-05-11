```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 
process_name="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE" 
AND Image="C:\\Program Files\\Mozilla Firefox\\firefox.exe" 
AND CommandLine="*www.*"
| table _time Image, CommandLine, process_name, User, host


```