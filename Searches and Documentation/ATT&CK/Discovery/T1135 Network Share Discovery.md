# Network Share Discovery
Shared network drives may allow threat actors access to file directories on various other machines across the network. Sensitive documents may be stored on these devices and will enable a threat actor access. 

Mitre ID: T1135  
Permissions required: Discovery  
Tactic: Discovery  

## Executables Utilised
net.exe  
net1.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source:Sysmon
```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="net.exe" AND CommandLine="*view*")
OR (process_name="net.exe" AND CommandLine="*share*")
OR (process_name="net1.exe" AND CommandLine="*view*")
OR (process_name="net1.exe" AND CommandLine="*share*")
| table _time Image, CommandLine, process_name, User, host

```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
| net.exe|net view * |Displays a list of resources being shared on a machine. |
| net.exe|net share * |Causes a machine's resources to be available to network users.|

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1135/) |
|Microsoft|Offical docs on net.|[Link](https://docs.microsoft.com/en-us/windows/desktop/winsock/net-exe-2) |
