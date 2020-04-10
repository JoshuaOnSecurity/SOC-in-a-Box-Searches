# Remote System Discovery
Threat actors may attempt to discover other systems connected to a domain or network. Actors could then use this information to discover high value targets to move latterally around the network.

Miter ID: T1018  
Permissions required: User, Administrator, SYSTEM  
Tactic: Discovery  

## Executables Utilised
net.exe  
ping.exe  
arp.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.
You may want to excluse or drill down the results from ping.exe, depending on your enviroment.  

Input Source:Sysmon
```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(OriginalFileName="ping.exe") 
OR (OriginalFileName="net.exe" OR OriginalFileName="net1.exe" CommandLine="*net  view*")
OR (OriginalFileName="arp.exe")
OR (OriginalFileName="nltestrk.exe" AND CommandLine="*dclist*")
| table _time Image, CommandLine, ParentImage, User, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
| net.exe  | net view | Lists computers on current domain or network. |
| net.exe  | net view /domain | will list all of the sharing computers within the domain. | 
| arp.exe  | arp -a |  display's the arp cache tables for all interfaces.|

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.  
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.  
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.  

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1018/) |
|  Microsoft | Offical docs on Ping.  |   [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ping) |
|  Microsoft | Offical docs on net view.  |   [Link](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/gg651155(v%3Dws.11)) |
