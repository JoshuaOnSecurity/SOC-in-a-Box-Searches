# Windows Management Instrumentation
WMI is a Windows feature that provides an enviroment for local and remote access to Windows components. Threat actors can utilise WMI to interact with local and remote systems. Functions include information gathering and execution of malicious files. 

Miter ID: T1047  
Permissions required: User  
Tactic: Execution  

## Executables Utilised
wmic.exe


## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="wmic.exe" AND cmdline="*format*"
| table _time process_name, cmdline, parent_process, user, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|wmic.exe |Contains "format"|Could be an indicator of file being downloaded and executed. See references. |

## How to react
At this stage, WMIC would have been utilised to execute malicious code on an endpoint. It is critical to discover if the use of WMIC is malicious. The affected devices must be removed from the network. Investagation must be carried out to discover if other machines have been affected, the source of the WMIC execution, and normal incident response procedures must be followed. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link |[Link](https://attack.mitre.org/techniques/T1047/) |
|Microsoft|Offical docs on wmic.|[Link](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) |
|Microsoft Security|Blog post on WMIC being utilised by APT.|[Link](https://www.microsoft.com/security/blog/2019/07/08/dismantling-a-fileless-campaign-microsoft-defender-atp-next-gen-protection-exposes-astaroth-attack/) |
