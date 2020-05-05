# FYP Project
This reposity is for the backup / alternate access for my final year project. 

# Steps to reproduce
## Requirements
To deploy the artefact several requirements need to be satisifed.
* One Ubuntu server (tested on 18.04) machine, with the Ansible framework installed onto it (Ansible deployment node). 
* One Ubuntu server (tested on 18.04) machine, for the deployment of Splunk. 
* Atleast one Windows 10 machine for the deployment of Sysmon and the Splunk UF. 

## Stage one - Ansible Deployment
1) Move the Ansible playbooks and roles to the Ansible deployment node within the directory ```/etc/ansible/```. 
2) Edit the ```hosts``` file. Following the directions, add the IP addresses for the SIEM server and the Windows machine.
3) Choose to run the individual playbooks, or the main playbook for full automated deployment of the project solution.  
4) Ensure that Splunk is running by navagating to the web interface at ```http://<instanceIP>:8000``` and login using the credentials you provided.  
5) Ensure that the Splunk instance is receiving data to the sysmon index by navigating to ```settings >> data >> indexes```.  
6) If Splunk is receiving new Sysmon logs sent by the Windows machine, the deployment of all tooling was sucessful. 

## Stage two - Splunk searches
1)
2)
3) 
