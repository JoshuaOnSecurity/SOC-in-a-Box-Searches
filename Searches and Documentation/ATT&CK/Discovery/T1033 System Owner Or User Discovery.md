# System Owner Or User Discovery.md
Threat actors may attempt to enumerate users on a compromised machine. Usernames can be retrieved using a variety of methods
because user and username details are prevalent throughout a system and include running process ownership, file/directory
ownership, session information, and system logs. This can make identifying enumeration tricky through alerting. However, malware and
APT groups are known to use basic windows executables to discover the system owner. 

Mitre ID: T1033  
Permissions required: User, Administrator  
Tactic: Discovery

## Executables Utilised
whoami.exe  
hostname.exe  
query.exe  
quser.exe  
qwinsta.exe  
wmic.exe  

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon  
```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(OriginalFileName="whoami.exe")
OR (OriginalFileName="hostname.exe")
OR (OriginalFileName="query.exe" AND CommandLine="*session*")
OR (OriginalFileName="quser.exe")
OR (OriginalFileName="qwinsta.exe")
OR (wmic.exe AND CommandLine="*useraccount*")
| table _time Image, CommandLine, ParentImage, User, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
| whoami.exe |whoami |Lists the current user. An unusual command for a normal user to run. |
| whoami.exe |whoami /all |Displays all information in the current access token, including the current user name, security identifiers (SID), privileges, and groups that the current user belongs to.  |
| hostname.exe | hostname | Displays the machine's hostname. |
| query.exe | query session | Displays details of the current session.|
|quser| quser |Same as query user command. |
|qwinsta.exe| qwinsta |Same as query session. | 

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.  
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.  
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.  

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre | Mitre link. | [Link](https://attack.mitre.org/techniques/T1033/)|
| Microsoft | Offical docs on whoami. |[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami) |
| Microsoft | Offical docs on hostname. |[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/hostname)|
| Microsoft | Offical docs on query. | [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/query)|
| Microsoft | Offical docs on qwinsta. | [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/qwinsta)|
| Microsoft | Offical docs on quser | [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/quser)|
