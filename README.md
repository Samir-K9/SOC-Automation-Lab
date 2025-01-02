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
### Step 1 : Install Windows 10 on VMware along with Sysmon.
- **Install Windows 10 on VMware and download Sysmon.**
- **Download Sysmon configuration file from [Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular)**
- **Extract files from downloaded Sysmon Zip file and place the configuration file in the same directory.**
- **Finally run Powershell as Administrator and change to the same directory as Sysmon and install it using the command: .\Sysmon64.exe -i .\sysmonconfig.xml**
  ![Image Alt](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/VirtualBox_Demo_01_01_2025_19_18_41.png?raw=true)
- **Verify Sysmon is installed by checking Services that are currently running.**
  ![Image Alt](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/VirtualBox_Demo_01_01_2025_19_19_19.png?raw=true)

  ### Step 2 : Build Wazuh Server on DigitalOcean.
 - **Create a new droplet on DigitalOcean to setup the Wazuh Server with following specifications:**
   - Operating System: Ubuntu 22.04(LTS)x64
   - Droplet Type: Basic
   - CPU Options: Premium Intel(8GB RAM 160GB Storage)
   - Password: (Create our own root password)
   - Hostname: Wazuh
  - **Setup firewall by selecting Networking on the left-hand side and click on Firewalls tab.**
  - **Modify Inbound firewall rules to only allow access from our own Public IP address by adding our address in the source.**
    ![Image Alt](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-01%20194539.png?raw=true)
  - **Apply new firewall rules to the Wazuh Server by adding Wazuh droplet to the firewall.**
    ![Image Alt](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-01%20195931.png?raw=true)
  - **Connect to the Wazuh Server by using SSH and run the following commands to update and upgrade the system and install Wazuh:**
    ```
    sudo apt-get update && sudo apt-get upgrade
    ```
    ```
    curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
    ```
  - **Copy the username and password and access the Wazuh Web Interface and login with those credentials.**
    ![Image Alt](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-01%20201342.png?raw=true)

    ### Step 3 : Build TheHive on DigitalOcean.
  - **Follow all the same steps on DigitalOcean to host TheHive same as Wazuh and add the same firewall rules to the droplet.**
  - **Connect to TheHive by using SSH and install pre-requisites.**
    - Install dependencies
      ```
      apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
      ```
    - Install Java
      ```
      wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
      echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
      sudo apt update
      sudo apt install java-common java-11-amazon-corretto-jdk
      echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
      export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
      ```
    - Install Cassandra
      ```
      wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
      echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a 
      /etc/apt/sources.list.d/cassandra.sources.list
      sudo apt update
      sudo apt install cassandra
      ```
    - Install ElasticSearch
       ```
      wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
      sudo apt-get install apt-transport-https
      echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee 
      /etc/apt/sources.list.d/elastic-7.x.list
      sudo apt update
      sudo apt install elasticsearch
      ```
    - Optional ElasticSearch Configuration : Create a jvm.options file under /etc/elasticsearch/jvm.options.d and put the following configurations in that file.
      ```
      Dlog4j2.formatMsgNoLookups=true
      Xms2g
      Xmx2g
      ```
    - Install TheHive
        ```
      wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
      echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a 
      /etc/apt/sources.list.d/strangebee.list
      sudo apt-get update
      sudo apt-get install -y thehive
      ```
- **Configure Cassandra by modifying the following file:**
     ```
     nano /etc/cassandra/cassandra.yaml
     ```
  - Change listen_address to Public IP of TheHive (178.128.228.152)
  - Change rpc_address to Public IP of TheHive (178.128.228.152)
  - Change seeds to Public IP of TheHive (178.128.228.152:7000)

- **Stop Cassandra Service:**
     ```
     systemctl stop cassandra.service
     ```
- **Remove old files from Cassandra as it was used to install TheHive.**
     ```
     rm -rf /var/lib/cassandra/*
     ```
- **Restart Cassandra and check status.**
     ```
     systemctl start cassandra.service
     systemctl status cassandra.service
     ```
- **Setup ElasticSearch by modifying the following file.**
  ```
  nano /etc/elasticsearch/elasticsearch.yml
   ```
  - Remove the comment and change cluster.name to thehive
  - Remove the comment for node.name
  - Remove the comment and change network.host to Public IP of TheHive (178.128.228.152)
  - Remove the comment from http.port
  - Remove the comment from cluster.initial_master_nodes and remove node-2

- **Start and enable ElasticSearch and check its status.**
  ```
  systemctl start elasticsearch
  systemctl enable elasticsearch
  systemctl status elasticsearch
   ```
- **Make sure thehive user and group have access to certain file paths.**
- thehive needs access to this file path.
  ```
  ls -la /opt/thp
  ```
- If root has access to thehive directory, change it using the following command:
 ```
 chown -R thehive:thehive /opt/thp
 ```
- **Configure thehive configuration file.**
  ``` 
  nano /etc/thehive/application.conf
  ```
   - Change database and index configurations hostnames to Public IP of TheHive (178.128.228.152)
   - Change cluster-name to same as Cassandra if changed (Test Cluster)
    - Change application.baseURL to Public IP of TheHive (http://178.128.228.152:9000)
  
- **Start and enable TheHive and check status.** 
  ``` 
  systemctl start thehive
  systemctl enable thehive
  systemctl status thehive
  ```
     

  


  
     
     
     
  
  
       
      

    
    




