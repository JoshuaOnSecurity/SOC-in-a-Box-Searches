# Compiled HTML File
Compiled HTML files are distrubuted as part of the Microsoft HTML Help System. These files are loaded by the HTML Help executable(hh.exe) Threat actors can abuse this techlogy to conceal malicious code, leading to payload execution or application whitelist bypassing.

Miter ID: T1223  
Permissions required: User  
Tactic: Execution, Defence Evasion

## Executables Utilised
hh.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have be blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="hh.exe"
| table _time Image, CommandLine, process_name, User, host

```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|hh.exe |hh.exe <malicious.chm> |User executing a malicious chm file.|

## How to react
When this alert triggers, the first stage is to discover if the CHM file is malicious. This can be discovered using a few differnt tatics. 
Perform analysis of execution arguments. Compare recent use of hh.exe and compare against known good execution arguments. 
Perform analysis of non-standard parent processes. For instance, you would not expect a parent process of cmd.exe, this may indicate manual executution by the user. 
If the CHM file and execution is considered malicious, follow standard prodedures on isolation and incident response. Also perform investagation to see if any other machines are potentially infected. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link |[Link](https://attack.mitre.org/techniques/T1223/) |
| Trend Micro | Trend Micro definition on malicious CHM files. | [Link](https://www.trendmicro.com/vinfo/us/security/definition/CHM)
|  Github (mgeeky) |Details on creating a malicious CHM file. |[Link](https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7) |
| Lolbas | Lolbas deatils on hh.exe | [Link](https://lolbas-project.github.io/lolbas/Binaries/Hh/) | 

# To Do
Create Powershell Search
