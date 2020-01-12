# Domain Trust Discovery
Threat actors may attempt to enumerate trust relationships on the domain to discover lateral movement opportunities. Domain trust can be enumerated a by utilising Win32 API, .NET, LDAP and the utilisation of executables. 

Mitre ID: T1482  
Permissions required: User  
Tactic: Discovery  

## Executables utilised
dsquery.exe  
nltest.exe


## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name="nltest.exe" OR process_name="dsquery.exe"
| table _time process_name, cmdline, parent_process, user, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
| nltest.exe| nltest /domain_trusts| Returns a list of trusted domains.|
| nltest.exe| nltest /domain_trusts /all_trusts| Returns a list of all trusted domains.|
| nltest.exe| nltest /domain_trusts /trusted_domains| Returns a list of trusted domains.|
| dsquery.exe| dsquery * -filter "(objectClass=trustedDomain)" -attr * | Provides information on trusted domains.|

## How to react
Generally, these commands can be used by processes and system administrators daily. When alerting its essential to locate outliers that may indicate compromise.  
For example, a user who works in finance would not be expected to use these commands. However, a system administrator utilises these commands to troubleshoot an issue.  
Correlating events is essential. If you are seeing a range of commands being used on one machine or several machines, this may be an indication of compromise on the network.  


## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1482/) |
| Microsoft  | Offical docs on nltest.  |   [Link](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v%3Dws.11)) |
| Microsoft |Offical docs on dsquery. | [Link](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v%3Dws.11))
