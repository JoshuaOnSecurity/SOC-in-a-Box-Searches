# AtBroker.exe
A binary to launch assistive technologies such as on screen keyboard.  

## Prerequisites 
Before the following Splunk search will work, ensure you have following added to your Sysmon configuration, for event ID 12, 13 & 14. 
```xml
<TargetObject condition="contains">\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration</TargetObject>
<TargetObject condition="contains">\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs</TargetObject>
```

## Splunk Search
```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
OR (EventCode=13 AND TargetObject="*Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility")
OR (EventCode=12 OR EventCode=13 AND TargetObject="*Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs*")
NOT (cmdline=ATBroker.exe AND ParentCommandLine=winlogon.exe)
| table _time process_name, cmdline, parent_process, user, host
```

## What to look for
Look for unauthorised execution of AT’s using ATBroker.exe(see example on LOBAS).  
Look for unknown AT’s being added to the AT registry, and then a new key being added to Accessibility to cause persistence.  

## How to react
Any unauthorised registry key changes to /ATs/or 3rd party applications started with AtBroker should be regarded as highly suspicious, and the cause should be investigated immediately. 

## Resources

| Source | Descirption | Link | 
| --- | --- | --- |
| LOBAS  |LOBAS Link.|[Link](https://lolbas-project.github.io/lolbas/Binaries/Atbroker/) |
|Mitre |Mitre Link. |[Link](https://attack.mitre.org/techniques/T1218/) |
|Hexacorn|Further details on AtBroker Persistence.|   [Link](http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/) |

