# FYP Project  
This repository is for the backup / alternate access for my final year project.   

# Steps to reproduce
## Requirements
To deploy the artefact several requirements need to be satisfied  
* One Ubuntu server (tested on 18.04) machine, with the Ansible framework installed onto it (Ansible deployment node). 
* One Ubuntu server (tested on 18.04) machine, for the deployment of Splunk. 
* At least one Windows 10 machine for the deployment of Sysmon and the Splunk UF. 

## Stage one - Ansible Deployment  
1) Move the Ansible playbooks and roles to the Ansible deployment node within the directory ```/etc/ansible/```. 
2) Edit the ```hosts``` file. Following the directions, add the IP addresses for the SIEM server and the Windows machine. Also add the user/service accounts. These must have admin privlages.  
3) Choose to run the individual playbooks, or the main playbook for full automated deployment of the artefact.  
4) Ensure that Splunk is running by navigating to the web interface at ```http://<instanceIP>:8000``` and login using the credentials you provided.  
5) Ensure that the Splunk instance is receiving data to the sysmon index by navigating to ```settings >> data >> indexes```.  
6) If Splunk is receiving new Sysmon logs sent by the Windows machine, the deployment of all tooling was successful.  

## Stage two - Splunk searches  
1) To access Splunk searches navigate to ```settings >searches, reports and alerts ```, from here you can run and view saved searches.   
2) Run suspicious commands on the Windows endpoint such as ```whoami ```.  
3) Wait for alert to trigger or force and alert to trigger by pressing ```run ```.  
