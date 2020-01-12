# System Service Discovery
Threat actors may attempt to gather information about registered services. The information can be used to discover potential vulnerabilities or discover further information for targeted attacks.  

Miter ID: T1007  
Permissions required: User, Administrator, SYSTEM  
Tactic: Discovery  

## Executables Utilised
sc.exe  
net.exe  
net1.exe  
wmic.exe  

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon  
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="sc.exe" AND cmdline="*query*") 
OR (process_name="sc.exe" AND cmdline="*start*") 
OR (process_name="sc.exe" AND cmdline="*stop*") 
OR (process_name="net.exe" AND cmdline="*start*")
OR (process_name="net1.exe" AND cmdline="*start*")
OR (process_name="wmic.exe" AND cmdline="*service  where*")
| table _time process_name, cmdline, parent_process, user, host
```
Input Source: Powershell  
```
index=powershell_logs
(Message="*tasklist*")
OR (Message="*sc query*")
OR (Message="*sc start*")
OR (Message="*sc stop*")
OR (Message="*net start*")
OR (Message="*wmic service where*")
| table _time EventCode Message host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|sc.exe |sc query | Query's a service.|
| net.exe  | net start |Starts a service.|

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1007/) |
| Microsoft  |   Offical doc's on net.exe.  |   [Link](https://docs.microsoft.com/en-us/windows/desktop/winsock/net-exe-2) |
| Microsoft  | Offical doc's on Tasklist.  |   [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist) |
| Microsoft  |   Offical doc's on sc.exe.  |   [Link](https://support.microsoft.com/en-gb/help/251192/how-to-create-a-windows-service-by-using-sc-exe) |
