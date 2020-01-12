# Password Policy Discovery
Threat actors may discover Password policy's to narrow down possible credentials for brute force attacks. An attacker could also prevent lockout on brute force attacks as they would discover the lockout threshold.

Mitre ID: T1201  
Permissions required: User  
Tactic: Discovery  

## Executables Utilised
net.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have be blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="net.exe" AND cmdline="*accounts*")
OR (process_name="net1.exe" AND cmdline="*accounts*")
| table _time process_name, cmdline, parent_process, user, host
```
Input Source: Powershell
```
index=win10sec_powershell_logs
(Message="*net*" AND Message="*accounts*")
OR (Message="*Get-PassPol*")
| table _time EventCode Message host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|net.exe|net accounts | Password policy of the current machine.|
|net.exe|net accounts /domain |Password policy set on the domain controller. |

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.  
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.  
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.  
## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1201/) |
| Microsoft  |Offical docs on net.  |   [Link](https://support.microsoft.com/en-gb/help/556003) |
