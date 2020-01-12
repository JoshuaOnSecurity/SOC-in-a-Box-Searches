# Mshta
Mshta.exe is a Microsoft utility for executing HTA files. Threat actors can use this utility to proxy execution of malicious files. Mshta can be used to bypass application whitelisting and also bypass browser security settings. 

Miter ID: T1170  
Permissions required: User  
Tactic: Defense Evasion, Execution

## Executables Utilised
Mshta.exe


## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="mshta.exe" OR cmdline="*.hta*" OR file_path="*.hta*")
| table _time process_name, cmdline, parent_process, ParentCommandLine, user, host
```
Input Source: Powershell
```
Powershell
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|Mshta.exe |Mshta.exe <malicious files / URL> |Loading a malicious hta file with mshta. |

## How to react
If HTA files are not typically used within your environment, this alert should be considered a high priority. It will be essential to determine the source of the HTA file and if Mshta.exe has been executed maliciously. Command arguments used before and after the mshta.exe invocation may be useful in determining the origin and purpose of the binary being executed. If the command is determined to be malicious, follow standard incident response procedures. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link |[Link](https://attack.mitre.org/techniques/T1170/) |
