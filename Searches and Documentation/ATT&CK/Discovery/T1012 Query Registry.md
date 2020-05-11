# Query Registry
Threat actors may interact with the Windows registry to gather information on the system, configuration and installed software.

Mitre ID: T1012  
Permissions required: User  
Tactic: Discovery  

## Executables Utilised
reg.exe


## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
CommandLine="*reg*" AND CommandLine="*query*"
| table _time Image, CommandLine, Parent_process, User, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|reg.exe |reg query * |User or process querying the registry. |

## How to react
A large number of registry queries can be considered unusual depending on the environment. It is also essential to check the registry that is being queried. If the registry is relating to sensitive software such as AV or Sysmon. It can be considered a reliable indicator of compromise and should be investigated immediately. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1012/) |
| Microsoft  |Offical docs on reg.   |   [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg) |
