# Account Discovery
Threat actors may attempt to enumerate local system or domain accounts. This information can be valuable for further attacks after initial entry into a network. 

Miter ID: T1087  
Permissions required: User  
Tactic: Discovery

## Executables utilised
net.exe  
net1.exe  
dsquery.exe  
cmdkey.exe  
query.exe  

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon  
```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(OriginalFileName="net.exe" AND CommandLine="*user*") 
OR (OriginalFileName="net1.exe" AND CommandLine="*user*")
OR (OriginalFileName="net.exe" AND CommandLine="*group*")
OR (OriginalFileName="net1.exe" AND CommandLine="*group*") 
OR (OriginalFileName="cmdkey.exe" AND CommandLine="*list*") 
OR (OriginalFileName="query.exe" AND CommandLine="*user*") 
OR (OriginalFileName="dsquery.exe")  
| table _time Image, CommandLine, ParentImage, User, host

```

## Suspicious Commands
These commands will be picked up by the above Splunk search and are not commonly run by users.

| Process  | Command | Description
| ------------- | ------------- | ------------ |
| net.exe  | net localgroup | Displays local groups (go figure). |
| net.exe  | net user | Lists local users. |
| net.exe  | net user /domain | Lists all the domain users. |
| net.exe  | net user administrator | Lists network administrators. A few variations of this. |
| net.exe  | net group "Domain Controllers" /domain | Lists domain controllers for the domain. |
| query.exe  | query user | Enumerate logged on users. |
| cmdkey.exe  | cmdkey.exe \all | Displays the list of stored user names and credentials. |
| dsquery.exe  |dsquery user |  Finds users in the directory who match the search criteria specified.|

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.  
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.  
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.  

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
| Mitre | Mitre link. | [Link](https://attack.mitre.org/techniques/T1087/) |
| Microsoft | Offical docs on dsquery. | [Link](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v%3Dws.11))
| Microsoft | Offical docs on net user.|[Link](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v%3Dws.11))
|Microsoft |Offical docs on cmdkey. |[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey)
|Microsoft |Offical docs on query user. |[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/query-user)|

## To Do
Make PowerShell alert more efficient. 
