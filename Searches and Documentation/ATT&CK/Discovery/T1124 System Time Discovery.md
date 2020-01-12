# System Time Discovery
Malware or threat actors may attempt to discover time zones or time of infection. The results can be used to get a victims location or to execute a file with Scheduled Task. 

Mitre ID: T1124  
Tactic: Discovery  
Permissions Required: User

## Executables Utilised
net.exe  
w32tm.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon  
``` 
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="net.exe" AND cmdline="*time*") 
OR  (process_name="w32tm.exe" AND cmdline="*/tz*") 
OR (process_name="net1.exe" AND cmdline="*time*")
|table _time, process_name, cmdline, parent_process, user, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
| net.exe | net time | Can gather system time or the time of other machines on the domain.|
| w32tm.exe | w32tm /tz | Displays system time zone. |

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.  
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.  
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.  

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1124/) |
|  Microsoft Blog | Information on w32tm and net time.  |   [Link](https://blogs.msdn.microsoft.com/w32time/2009/08/07/net-time-and-w32time/) |
