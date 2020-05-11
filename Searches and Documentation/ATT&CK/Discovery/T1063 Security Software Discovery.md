# Security Software Discovery
Threat actors may attempt to discover security software, configuration, defensive tools and sensors implemented on a system to avoid detection. 

Mitre ID: T1063  
Permissions required: User  
Tactic: Discovery  

## Executables Utilised
fltMC.exe  
findstr.exe  
reg.exe  
netsh.exe  
tasklist.exe  

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name ="netsh.exe" AND CommandLine="*firewall*")
OR (process_name="tasklist.exe" AND CommandLine="*findstr*")
OR (process_name="fltmc.exe")
OR (process_name="findstr.exe")
OR (process_name="reg.exe" OR CommandLine="*Microsoft-Windows-Sysmon/Operational*")
| table _time Image, CommandLine, process_name, User, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|netsh.exe |netsh firewall * | Displays details about the firewall|
|tasklist.exe | findstr * |Indicates a user searching for specific software. |
|reg.exe | * sysmon *  | Indicates a user querying the registry for Sysmon.|
| fltMC.exe  | fltmc |Indicates a user searching for specific software. |
| findstr.exe |findstr * |Indicates a user searching for specific software. | 

## How to react
Some of these commands should be considered highly unusual. If an alert is triggered, an investigation into the cause must be carried out. If the source is deemed malicious, normal incident response processes should be followed. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1063/) |
|Microsoft|Offical docs on fltMC.|[Link](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/development-and-testing-tools)|
|Microsoft|Offical docs on findstr.|[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr)|
|Microsoft|Offical docs on reg.|[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg)|
|Microsoft|Offical docs on tasklist.|[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist) 
|Microsoft|Offical docs on netsh.|[Link](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts)|

## To Do
Include Powershell search.

