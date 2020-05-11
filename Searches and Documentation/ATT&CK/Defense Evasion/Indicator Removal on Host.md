# Indicator Removal on Host
Threat actors may remove or alter logs in order to make analysis or alerting more difficult, due to lack of sufficent data.

Miter ID: T1070  
Permissions required: Administrator  
Tactic: Defence Evasion  

## Executables Utilised
wevtutil.exe  
fsutil.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have be blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="*wevtutil*")
OR (process_name="*fsutil*")
| table _time Image, CommandLine, process_name, User, host
```

Input Source: Windows Event Logs
```
sourcetype="WinEventLog"
(EventCode=1102)
|table _time, TaskCategory, LogName,  user, Security_ID, Account_Name, Logon_ID, ComputerName
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|wevtutil.exe |wevtutil cl security |User/process attempting to remove security logs |
|wevtutil.exe |wevtutil cl application |User/process attempting to remove application logs |
|wevtutil.exe |wevtutil cl system |User/process attempting to remove system logs |
|fsutil.exe |fsutil usn deletejournal |Manages the update sequence number change journal, which provides a persistent log of all changes made to files on the volume. |

## How to react
Logs should never be cleared on a production enviroment. The attempted or sucsesful log clear should be investagated imidetly and the cause should be found. In the event the cause is malicious, regular incident response and isolation procedures should be followed. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1070/) |
| Microsoft|Offical docs on wevtutil.exe.|[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)|
|Microsoft|Offical docs on Fsutil.exe.|[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil)|
