# System Information Discovery
Threat actors may attempt to gain detailed information on the infected system. This could include OS versions, service packs, architecture and system hardware. 

Miter ID: T1082  
Permissions required: User  
Tactic: Discovery  

## Executables Utilised
systeminfo.exe  
reg.exe  

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="systeminfo.exe") 
OR (process_name="reg.exe" AND cmdline="*HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum*") 
| table _time process_name, cmdline, parent_process, user, host
```
Input Source: Powershell  
Message="*set*" May return a lot of results and require filtering.
```
index=powershell_logs
(Message="*systeminfo*")
OR (Message="*reg*" AND Message="*query*" AND "*HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum*") 
OR (Message="*set*") 
| table _time EventCode Message host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|systeminfo.exe | systeminfo|Prints out vast amounts of system information. Not commonly run by normal users. |
|reg.exe |reg query |Users querying specific registry keys may provide insights on an attack. |

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1082/) |
|  Microsoft | Offical docs on systeminfo.|[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo) |
|  Microsoft | Offical docs on reg query.|[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query) |
