# Process Discovery
A threat actor may attempt to view running processes and the user who is running them.

Mitre ID: T1057  
Permissions required: User, Administrator, SYSTEM may provide better process ownership details.  
Tactic: Discovery  

## Executables Utilised
tasklist.exe  
qprocess.exe  
query.exe  

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Search discovers commands run utilising the above processes.   
Input Source: Sysmon
```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="qprocess.exe" 
OR (process_name="tasklist.exe")
OR (process_name="query.exe" CommandLine="query*" AND CommandLine="*process*")
| table _time Image, CommandLine, process_name, User, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|tasklist.exe |tasklist | Dumps a list of current processes.| 
|tasklist.exe | tasklist /v|     Displays verbose task information in the output.|
|tasklist.exe |tasklist /fi | Specifies the types of processes to include in or exclude from the query.| 
|tasklist.exe |tasklist /svc |Lists all the service information for each process without truncation. |
| tasklist.exe| tasklist /V /S 'PC Name'|Lists processes on remote machine. |
| qprocess.exe|qprocess * |Dumps a list of current processes. |
| query.exe| query process|Dumps a list of current processes. |

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.  
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.  
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.  

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link |[Link](https://attack.mitre.org/techniques/T1057/) |
| Microsoft  | Offical docs on Tasklist.  |   [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist) |
| Microsoft  |Offical docs on Qprocess.   |   [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/query-process) |
| Microsoft | Offical docs on query. | [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/query)|
