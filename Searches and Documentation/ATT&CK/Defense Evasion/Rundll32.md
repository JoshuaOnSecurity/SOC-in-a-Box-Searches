# Rundll32
Rundll32 is a process that can be utilised to execute an arbitrary binary. Threat actors may use this functionality to execute code, bypassing security tools or whitelists. Threat actors can also utilise Rundll32 to execute control panel item files(.cpl) and JavaScript. 

Miter ID: T1085  
Permissions required: User  
Tactic: Defense Evasion, Execution

## Executables Utilised
rundll32.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.


Input Source: Sysmon
```
sourcetype=
process_name=rundll32.exe AND cmdline="*javascript*"
| table 
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
| | | |

## How to react
Desc

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre|Mitre Link.|[Link](https://attack.mitre.org/techniques/T1085/)|
|   |   |   [Link]() |
