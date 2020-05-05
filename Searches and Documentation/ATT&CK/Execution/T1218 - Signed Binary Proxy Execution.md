# Requires review
```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="Msiexec.exe" 
OR OriginalFileName="Mavinject.exe" 
OR OriginalFileName="SyncAppvPublishingServer.exe" 
OR OriginalFileName="Odbcconf.exe"
| table _time Image, CommandLine, ParentImage, User, host
```