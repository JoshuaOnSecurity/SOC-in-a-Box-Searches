# Requires review
```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="Msiexec.exe" 
OR process_name="Mavinject.exe" 
OR process_name="SyncAppvPublishingServer.exe" 
OR process_name="Odbcconf.exe"
| table _time Image, CommandLine, process_name, User, host
```