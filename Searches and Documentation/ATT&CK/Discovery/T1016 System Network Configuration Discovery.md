# System Network Configuration Discovery
Threat actors may attempt to discover details on the systems network configuration or setting. Threat actors could then use this information to move laterally around the network. It is also typical for malware to run commands on first execution, to discover information such as a machines IP address.  

Mitre ID: T1016  
Permissions required: User  
Tactic: Discovery  

## Executables Utilised
nbtstat.exe  
ipconfig.exe  
getmac.exe  
net.exe  
netsh.exe  
route.exe  

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon  
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="ipconfig.exe" AND cmdline="*ipconfig  /all*")
OR (process_name="nbtstat.exe")
OR (process_name="getmac.exe")
OR (process_name="net.exe" AND cmdline="*config*")
OR (process_name="netsh.exe" AND cmdline="*interface*")
OR (process_name="route.exe" AND cmdline="*print*")
| table _time process_name, cmdline, parent_process, user, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|route.exe |route print |Provides information such as route tables and interfaces. |
|ipconfig.exe |ipconfig /all |Displays full TCP/IP configuration for all adapters. |
|getmac.exe |getmac |Dumps the device MAC address |
|net.exe |net config |Displays details on servers or workstations. |
|netsh.exe | netsh interface * |Can display a variety of useful information depending on the arguments. |
|nbtstat.exe |nbtstat -n |Displays NetBIOS TCP/IP details. |

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.
Correlating events is essential. If you see a range of commands used on one machine or several machines, this may be an indication of compromise on the network.

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1016/) |
|Microsoft | Offical nbtstat docs. |   [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/nbtstat) |
|Microsoft| Offical ipconfig docs.|   [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig) |
|Microsoft | Offical getmac docs.|   [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/getmac) |
| Microsoft| Offical net config docs.  | [Link](https://support.microsoft.com/en-gb/help/556004) |
| Microsoft| Offical netsh docs.| [Link](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) |

# To Do
Provide route source. 
