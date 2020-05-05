# BITS Jobs
Windows Background Intelligent Transfer Service is designed to operate in the background of Windows without interrupting other networked applications. The goal is to perform asynchronous file transfer. Threat actors can use BITS to download, execute and clean up malicious code. BITS can also allow persistence by creating long-standing jobs or by invoking an arbitrary program when a job completes or errors (including after system reboots).

Miter ID: T1197  
Permissions required: User  
Tactic: Persistence  

## Executables Utilised
bitsadmin.exe

## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon  
This alert will show all useage of BITS. Depending on the enviroment and how often BITS is used, this alert may need to be edited. 
```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
OriginalFileName="bitsadmin.exe"
| table _time Image, CommandLine, ParentImage, User, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|bitsadmin.exe |bitsadmin /transfer |Transfers a file. |
|bitsadmin.exe |bitsadmin /create|Create a download job. |
|bitsadmin.exe |bitsadmin /addfile|Add a file to a job.  |
|bitsadmin.exe |bitsadmin /SetNotifyFlags|Allows for event generation. |
|bitsadmin.exe |bitsadmin /SetNotifyCmdLine|Sets command run when job finishes or enters state. |
|bitsadmin.exe |bitsadmin /SetMinRetryDelay|Sets the minimum length of time that BITS waits after encountering a transient error before trying to transfer the file. |
|bitsadmin.exe |bitsadmin /SetCustomHeaders|Adds a custom HTTP header to a GET request. |
|bitsadmin.exe |bitsadmin /Resume|Activates a new or suspended job in the transfer queue. |

## How to react
As BITS can be utilised for many reasons, first discover if the use of BITS has been malicious. Take not of the suspicious commands. If BITS usage is determined to be malicious, affected machine needs to be removed from the network and incident response procedures followed. An investagation on how the malicious useage of BITS happened, while discovering if any other systems have been affected. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1197/) |
|Microsoft|Offical docs on bitsadmin.|[Link](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin)|
|Microsoft Security|Bog post on APT activity utilising bitsadmin.|[Link](https://www.microsoft.com/security/blog/2019/07/08/dismantling-a-fileless-campaign-microsoft-defender-atp-next-gen-protection-exposes-astaroth-attack/)|
