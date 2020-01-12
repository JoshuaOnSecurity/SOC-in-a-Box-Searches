# Permission Groups Discovery
Threat actors may attempt to find local system or domain-level groups and permissions settings. Permission groups can aid the threat actor in discovering ways to move around a network laterally

Mitre ID: T1069  
Permissions required: User    
Tactic: Discovery  

## Executables Utilised
net.exe  
net1.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process="net.exe" OR process="net1.exe"
cmdline="*net*" AND cmdline="*localgroup*"
OR cmdline="*net*" AND cmdline="*group*"
OR cmdline="*net1*" AND cmdline=*"group*"
OR cmdline="*net1*" AND cmdline="*localgroup*"
| table  _time process, cmdline, parent_process, user, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
| net.exe |net localgroup |Displays local groups (go figure). |
| net.exe |net group /domain |Performs the operation on the domain controller in the current domain. |
| net.exe  | net group "Domain Controllers" /domain | Lists domain controllers for the domain. |

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.  
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.  
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.  

## Resources

| Source | Description | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1069/) |
|  Microsoft | Offical docs on net group. |[Link](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754051(v%3Dws.11)) |
|Microsoft | offical docs on net localgroup. | [Link](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc725622(v%3Dws.11))
