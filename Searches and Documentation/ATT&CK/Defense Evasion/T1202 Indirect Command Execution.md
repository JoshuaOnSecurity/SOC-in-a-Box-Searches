# Indirect Command Execution
Threat actors may utilise several Windows utilities in an attempt to avoid detection. Some of these executed commands may not invoke cmd. This form of defence evasion is mainly used to perform arbitrary execution, avoiding detection/mitigation controls. 

Miter ID: T1202  
Permissions required: User  
Tactic: Defense Evasion  

## Executables Utilised
pcalua.exe  
bash.exe  
forfiles.exe  

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="pcalua.exe")
OR (process_name="bash.exe")
OR (process_name="forfiles.exe")
| table _time process_name, cmdline, parent_process, user, host
```
Input Source: Powershell
```
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
| pcalua.exe|pcalua -a < process.exe > | User/process attempting to spawn a process using pcalua. |
| forfiles.exe|forfiles /p c:\windows\system32 /m notepad.exe /c process.exe | Executes process.exe |
|forfiles.exe|forfiles /p c:\windows\system32 /m notepad.exe /c "c:\folder\normal.dll:evil.exe"|Executes the evil.exe Alternate Data Stream. |
  
## How to react
Depending on your environment, it can be considered that the use of these utilities to spawn processes, commands or network connections is malicious. Attempt to discover the cause and follow standard incident response procedures. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link |[Link](https://attack.mitre.org/techniques/T1202/) |
| Lobas  | Lobas details on forfiles. Used in command examples.|[Link](https://lolbas-project.github.io/lolbas/Binaries/Forfiles/) |
| Microsoft| Offical Microsoft docs on forfiles. | [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/forfiles)|
