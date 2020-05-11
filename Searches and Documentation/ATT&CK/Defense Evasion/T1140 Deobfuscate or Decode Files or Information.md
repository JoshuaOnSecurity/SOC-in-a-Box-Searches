# Deobfuscate/Decode Files or Information
Threat actors may use obfuscated files to minimise detection and deter analysis. These actors may need to deobfuscate files before execution. Identifying the deobfscation process will be crucial to identifying malicious activity. 

Miter ID: T1140  
Permissions required: User  
Tactic: Defence Evasion  

## Executables Utilised
certutil.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="certutil.exe" AND CommandLine="*-encode*" 
OR (process_name="certutil.exe" AND CommandLine="*-decode*") 
| table _time process_name, CommandLine, user, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|certutil.exe |certutil -decode |Decode the contents of a malicious file. |

## How to react
First, identify if the use of processes is malicious. If the use was malicious, steps need to be taken to identify what the malicious code does once executed. It is also important to see if any other machines have been affected. Follow standard incident response procedures to resolve the issue. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1140/) |
| Microsoft  |Offical Microsoft docs on certutil.   |[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) |
| Microsoft Security  |Microsoft blog on APT activity that utilises certutil.|[Link](https://www.microsoft.com/security/blog/2019/07/08/dismantling-a-fileless-campaign-microsoft-defender-atp-next-gen-protection-exposes-astaroth-attack/) |
