# Windows Admin Shares
Threat actors could gain access to shares that are only accessible by administrators. This will give the threat actor the ability to copy files and other admin functions. 

Miter ID: T1077  
Permissions required: Administrator  
Tactic: Lateral Movement  

## Executables Utilised
net.exe  
net1.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
(process_name="net.exe AND cmdline="*$*")
OR (process_name="net1.exe AND cmdline="*$*")
| table _time process_name, cmdline, parent_process, user, host
```
Input Source: Powershell
```
index=powershell_logs
(Message="*net*" AND Message="*$*")
OR (Message="*New-PSDrive*" AND Message="*root*")
| table _time EventCode Message host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|net.exe | net use/session/file.../C$/IPC$/Admin$...|User attempting to access hidden network share. |
|Powershell.exe |New-PSDrive...filesystem -root... |User attempting to access hidden network share.  |

## How to react
Depending on your network, it is perfectly acceptable for a system administrator to access admin shares. However, it is essential to verify that the user did access that share personally, and not for a malicious intent. I.e. did they use their workstation? If not, standard incident response procedures should be followed. Another consideration is that passwords may be in plain text. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link |[Link](https://attack.mitre.org/techniques/T1077/) |
