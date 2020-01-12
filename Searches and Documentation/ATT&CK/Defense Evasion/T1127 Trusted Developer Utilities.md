# Trusted Developer Utilities
Theat actors may utilise software development related binaries to execute malicious code, potentially bypassing application whitelisting. Several Windows binaries that produce similar results. Refer to the Mitre documentation for more information.

Miter ID: T1127  
Permissions required: User  
Tactic: Defense Evasion, Execution 

## Executables Utilised
MSBuild.exe
dnx.exe
rcsi.exe
WinDbg.exe
cbd.exe
tracker.exe


## Splunk Searches
Splunk searches will need to be refined for your environment. Run this search over a long period of time and blacklist any noisy events from business-critical applications. Some fields may not match your environment. Specific commands may have been blacklisted or left out due to use in other searches within this repo, keeping alerting down to a minimum.

Input Source: Sysmon
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
process_name=msbuild.exe OR process_name=dnx.exe OR process_name=rcsi.exe OR process_name=windbg.exe OR process_name=tracker.exe OR cdb.exe
| table _time process_name, cmdline, parent_process, user, host
```

## Suspicious Commands
These commands are not commonly run by users and may be an indication of compromise.

| Process  | Command | Description
| ------------- | ------------- | -------- | 
|msbuild.exe |msbuild.exe *.csproj |Execute a C# project stored in a csproj file. |
|dnx.exe |dnx.exe ConsoleApp |Executes code located in the ConsoleApp folder. |
|rcsi.exe |rcsi.exe malicious.csx |Uses embedded C# within CSX script to execute code/bypass whitelists. |
|cbd.exe |cbd.exe -cf malicious.wds -o process.exe |Launch's malicious shellcode in process.exe, bypassing whitelists. |
|Tracker.exe |tracker.exe /d .\malicious.dll /c C:\Windows\process.exe|Injects arbitarary DLL into a target process st |


## How to react
In most environments, you would not normally expect these processes to execute. The alert should be a high priority alert. The cause should be investigated immediately, and in the event of malicious actions, incident response procedures should be followed. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
|Mitre |Mitre Link |[Link](https://attack.mitre.org/techniques/T1127/) |
|LOBAS|Detials on MSBuild.exe.|[Link](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/) |
|LOBAS|Detials on dnx.exe.|[Link](https://lolbas-project.github.io/lolbas/OtherMSBinaries/Dnx/) |
|LOBAS|Detials on rcsi.exe.|[Link](https://lolbas-project.github.io/lolbas/OtherMSBinaries/Rcsi/) |
|LOBAS|Detials on tracker.exe.|[Link](https://lolbas-project.github.io/lolbas/OtherMSBinaries/Tracker/) |
|Exploit Monday|Details on applicaion whitelisting bypass using WinDb.exe andd cdb.exe.|[Link](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html) |

