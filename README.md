# SOC-Automation-Lab

## Objective
The SOC Automation Lab project has been crucial in strengthening my understanding of security operations and developing my skills as a security analyst. I focused on using this platform to build skills in automating security operations. Working with different security tools gave me hands-on experience that improved my technical knowledge and ability to speed up threat detection and response through automation. 

### Skills Learned
- Developed automation skills for security processes, boosting operational efficiency and reducing manual errors.
- Created custom scripts for threat detection, such as identifying and mitigating sophisticated tools like Mimikatz, enhancing SOC capabilities against advanced cybersecurity threats.
- Gained expertise in systematic incident logging, analysis, and management, ensuring organized, strategic responses to security events.
- Improved proficiency in using threat intelligence platforms for in-depth analysis, boosting alert accuracy and threat mitigation.
- Acquired hands-on experience in configuring and managing security infrastructure across various environments, including cloud platforms, to support SOC operations.
- Enhanced skills in integrating and managing different operating systems within the SOC, ensuring a robust and comprehensive security posture.

## Prerequisites
### Hardware Requirements
- A host machine with adequate CPU, RAM, and disk space to support the VMs and their anticipated workloads.

### Software Requirements
- **VMware:** A software platform used for creating and managing virtual machines.
- **Windows 10:** A client device used to simulate real-world security threats, allowing for the testing and fine-tuning of SOC automation workflows.
- **Ubuntu 22.04:** Linux distribution for deploying Wazuh and TheHive which will be hosted on the cloud.
- **Sysmon:** A Windows system service and device driver that provides detailed information about system activity.

### Tools and Platforms
- **Wazuh:** An open-source security monitoring platform that provides intrusion detection, security information and event management (SIEM), and log management capabilities
- **Shuffle:** An open-source Security Orchestration, Automation, and Response (SOAR) platform designed to help security teams automate and streamline their security operations.
- **TheHive:** An open-source, scalable Security Incident Response Platform (SIRP) designed to assist security teams in managing, investigating, and responding to security incidents efficiently.
- **VirusTotal:** A free online service that analyzes files, URLs, and other potentially harmful content to detect malware, viruses, and other types of threats.
- **Digital Ocean:**  A cloud infrastructure provider that will host Wazuh and TheHive.
- **Mimikatz:** A widely-used open-source tool designed for post-exploitation activities in cybersecurity, particularly for testing the security of Windows environments.



## Workflow Overview
![Image Alt](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202024-12-23%20132100.png?raw=true)
*Ref 1: Network Diagram*

- **Telemetry Generation:** Mimikatz will be initiated on Windows 10 VM to simulate malicious behaviour which will generate telemetry data that will be captured by Sysmon.
- **Alert Generation:** Sysmon data is ingested by the Wazuh agent, which then forwards it to the Wazuh server. Alerts are then generated based on pre-set rules and configurations.
- **Alert Handling:** Shuffle receives the alerts from Wazuh and enriches Indicators of Compromise(IOCs) using VirusTotal for threat analysis.
- **Incident Management:** Shuffle sends alerts to TheHive which then creates cases for incident response and investigation.
- **Response Automation:** Analysts will select appropriate response actions in Shuffle, which then orchestrates the execution of these actions on the Wazuh agent through the Wazuh manager.

## Steps 
### Step 1 : Install Windows 10 on VMware along with Sysmon.**
- **Install Windows 10 on VMware and download Sysmon.**
- **Download Sysmon configuration file from [Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular)**
- **Extract files from downloaded Sysmon Zip file and place the configuration file in the same directory.**
- **Finally run Powershell as Administrator and change to the same directory as Sysmon and install it using the command: .\Sysmon64.exe -i .\sysmonconfig.xml**
  ![Image Alt](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/VirtualBox_Demo_01_01_2025_19_18_41.png?raw=true)
- **Verify Sysmon is installed by checking Services that are currently running.**
  ![Image Alt](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/VirtualBox_Demo_01_01_2025_19_19_19.png?raw=true)




