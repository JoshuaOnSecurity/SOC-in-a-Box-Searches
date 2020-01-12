# System Network Connections Discovery
Threat actors may attempt to list network connections on the compromised machine, or by querying over the network. 

Miter ID: T1049  
Permissions required: User  
Tactic: Discovery  

## Executables Utilised
net.exe  
net1.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have be blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="netstat.exe") 
OR (process_name="net.exe" AND cmdline="*use*")
OR (process_name="net.exe" AND cmdline="*sessions*")
OR (process_name="net.exe" AND cmdline="*file*")
OR (process_name="net1.exe" AND cmdline="*use*")
OR (process_name="net1.exe" AND cmdline="*sessions*")
OR (process_name="net1.exe" AND cmdline="*file*")
| table _time process_name, cmdline, parent_process, user, host
```
Input Source: Powershell
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="netstat.exe") 
OR (Message="*net*" AND Message="*use*")
OR (Message="*net*" AND Message="*sessions*")
OR (Message="*net*" AND Message="*file*")
OR (Message="*net1*" AND Message="*use*")
OR (Message="*net1*" AND Message="*sessions*")
OR (Message="*net1*" AND Message="*file*")
OR (Message=""*Get-NetTCPConnection*"")
| table _time EventCode Message host
```
## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
| net.exe| net use|Connects or disconects a machine from a shared resource. |
| net.exe| net file|Closes a shared file. |
| net.exe| net sessions| Displays information about all sessions with the machine. |
|netstat.exe|netstat|displays active TCP sessions.|
| Powershell.exe| Get-NetTCPConnection| Gets current TCP connections.|

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.  
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.  
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.  

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1049/) |
|Microsoft|Offical docs on net use.|[Link](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/gg651155(v%3Dws.11)) |
|Microsoft|Offical docs on net session. |[Link](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh750729(v%3Dws.11))|
|Microsoft |Offical docs on netstat. | [Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/netstat)|
|Microsoft   |Offical docs on Get-NetTCPConnection. |   [Link](https://docs.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=win10-ps) |

