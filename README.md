# SOC Automation Lab

> An end-to-end security operations workflow integrating Wazuh, TheHive, and Shuffle to automate threat detection, alert enrichment, and incident response.

![Platform](https://img.shields.io/badge/Platform-DigitalOcean-0080FF?logo=digitalocean&logoColor=white)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-005571?logo=wazuh&logoColor=white)
![SOAR](https://img.shields.io/badge/SOAR-Shuffle-purple)
![SIRP](https://img.shields.io/badge/SIRP-TheHive-orange)
![OS](https://img.shields.io/badge/OS-Ubuntu%2022.04-E95420?logo=ubuntu&logoColor=white)

---

## Overview

This lab simulates a real-world SOC environment where security events are automatically detected, enriched, and escalated — with minimal manual intervention. Mimikatz is used to generate adversarial telemetry on a Windows 10 VM, which flows through Sysmon → Wazuh → Shuffle → VirusTotal → TheHive, with email notifications sent to the analyst at each stage.

### Workflow

![Workflow Diagram](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202024-12-23%20132100.png?raw=true)

**Telemetry Generation** — Mimikatz executes on the Windows 10 VM and Sysmon captures process creation events.

**Alert Generation** — The Wazuh agent forwards Sysmon logs to the Wazuh server, which fires a custom rule (even if the Mimikatz binary is renamed).

**IOC Enrichment** — Shuffle receives the alert, parses the SHA256 hash, and checks its reputation against VirusTotal.

**Incident Management** — Shuffle creates a case in TheHive for analyst investigation.

**Response** — The analyst receives an email notification and can trigger response actions through Shuffle back to the Wazuh agent.

---

## Prerequisites

### Hardware
- Host machine with CPU, 8 GB+ RAM, and 100 GB+ free disk to run VMs

### Software
| Component | Purpose |
|-----------|---------|
| VMware / VirtualBox | VM host |
| Windows 10 | Client VM — simulates attacker activity |
| Ubuntu 22.04 LTS | Server OS for Wazuh and TheHive (cloud-hosted) |
| Sysmon | Detailed Windows telemetry collection |

### Tools & Platforms
| Tool | Category | Description |
|------|----------|-------------|
| [Wazuh](https://wazuh.com) | SIEM | Intrusion detection, log management, and alerting |
| [Shuffle](https://shuffler.io) | SOAR | Security orchestration and workflow automation |
| [TheHive](https://thehive-project.org) | SIRP | Incident response and case management |
| [VirusTotal](https://virustotal.com) | Threat Intel | Hash and IOC reputation analysis |
| [DigitalOcean](https://digitalocean.com) | Cloud | Hosts Wazuh and TheHive droplets |
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | Red Team | Post-exploitation tool for adversary simulation |

---

## Setup Guide

### Step 1 — Install Windows 10 + Sysmon

1. Create a Windows 10 VM in VMware.
2. Download [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and the [sysmon-modular config](https://github.com/olafhartong/sysmon-modular).
3. Place the config file in the same directory as the Sysmon executable.
4. Install Sysmon as Administrator:
   ```powershell
   .\Sysmon64.exe -i .\sysmonconfig.xml
   ```

   ![Sysmon install](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/VirtualBox_Demo_01_01_2025_19_18_41.png?raw=true)

5. Verify installation via **Services** — Sysmon should appear as a running service.

   ![Sysmon service running](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/VirtualBox_Demo_01_01_2025_19_19_19.png?raw=true)

---

### Step 2 — Deploy Wazuh on DigitalOcean

1. Create a new droplet:
   - OS: Ubuntu 22.04 (LTS) x64
   - Type: Basic — Premium Intel (8 GB RAM, 160 GB Storage)
   - Hostname: `Wazuh`

2. Under **Networking → Firewalls**, restrict inbound rules to your public IP only.

   ![Wazuh firewall rules](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-01%20194539.png?raw=true)

3. Apply the firewall to the Wazuh droplet.

   ![Wazuh firewall applied](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-01%20195931.png?raw=true)

4. SSH in and install Wazuh:
   ```bash
   sudo apt-get update && sudo apt-get upgrade
   curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
   ```

5. Save the generated credentials and log in to the Wazuh web dashboard.

   ![Wazuh dashboard](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-01%20201342.png?raw=true)

---

### Step 3 — Deploy TheHive on DigitalOcean

1. Create a second droplet (same specs as Wazuh) and apply the same firewall rules.

2. SSH in and install dependencies:
   ```bash
   apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl \
     software-properties-common python3-pip lsb-release
   ```

3. Install Java, Cassandra, Elasticsearch, and TheHive:

<details>
<summary>Expand full install commands</summary>

**Java:**
```bash
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update && sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

**Cassandra:**
```bash
wget -qO- https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update && sudo apt install cassandra
```

**Elasticsearch:**
```bash
wget -qO- https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update && sudo apt install elasticsearch
```

**TheHive:**
```bash
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update && sudo apt-get install -y thehive
```
</details>

4. Configure Cassandra (`/etc/cassandra/cassandra.yaml`) — set `listen_address`, `rpc_address`, and `seeds` to TheHive's public IP. Then reset the data directory:
   ```bash
   systemctl stop cassandra.service
   rm -rf /var/lib/cassandra/*
   systemctl start cassandra.service
   ```

5. Configure Elasticsearch (`/etc/elasticsearch/elasticsearch.yml`) — set `cluster.name: thehive`, `network.host` to TheHive's public IP, and remove `node-2` from `cluster.initial_master_nodes`. Then start and enable:
   ```bash
   systemctl start elasticsearch && systemctl enable elasticsearch
   ```

6. Ensure TheHive has access to its data path:
   ```bash
   chown -R thehive:thehive /opt/thp
   ```

7. Configure TheHive (`/etc/thehive/application.conf`) — update database/index hostnames, `cluster-name`, and `application.baseUrl`.

8. Start TheHive and navigate to `http://<THEHIVE_IP>:9000`:
   ```bash
   systemctl start thehive && systemctl enable thehive
   ```
   Default credentials: `admin@thehive.local` / `secret`

   ![TheHive dashboard](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-02%20140920.png?raw=true)

---

### Step 4 — Configure Wazuh Agent (Windows 10)

1. In the Wazuh dashboard, add a Windows agent using the Wazuh server's public IP and copy the install commands.

   ![Wazuh agent setup](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-02%20142048.png?raw=true)

2. Run the commands in an elevated PowerShell on the Windows 10 VM.

   ![Wazuh agent install](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/VirtualBox_Demo_02_01_2025_20_38_20.png?raw=true)

3. Start the Wazuh service:
   ```powershell
   net start wazuhsvc
   ```

4. Confirm one active agent appears in the Wazuh dashboard.

   ![Wazuh active agent](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-02%20205252.png?raw=true)

---

### Step 5 — Generate Telemetry and Build Detection Rule

1. Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` — remove Application, Security, and System log sections so only Sysmon events are forwarded.

   ![ossec.conf edit](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/VirtualBox_Demo_02_01_2025_21_42_04.png?raw=true)

2. Restart the Wazuh service under Services.

   ![Wazuh service restart](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/VirtualBox_Demo_02_01_2025_21_45_55.png?raw=true)

3. Download Mimikatz (temporarily disable Defender or exclude the directory), then execute it in PowerShell.

   ![Mimikatz execution](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/VirtualBox_Demo_02_01_2025_21_55_42.png?raw=true)

4. On the Wazuh server, enable full log archiving and restart services:
   ```bash
   nano /var/ossec/etc/ossec.conf   # Set <logall> and <logall_json> to yes
   systemctl restart wazuh-manager.service

   nano /etc/filebeat/filebeat.yml  # Set enabled: true
   systemctl restart filebeat
   ```

5. In the Wazuh dashboard, create a `wazuh-archives-*` index under **Stack Management → Index Management**. Mimikatz logs should now appear.

   ![Mimikatz logs in Wazuh](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-02%20222437.png?raw=true)

6. Create a custom detection rule under **Management → Rules → Custom Rules** (`local_rules.xml`) using the `originalFileName` field — this fires even if the attacker renames the binary.

   ![Sysmon rule reference](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-02%20224115.png?raw=true)
   ![Custom rule editor](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-02%20224506.png?raw=true)

7. Test the rule by renaming `mimikatz.exe` to `potato.exe` and executing it.

   ![Renamed Mimikatz test](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/VirtualBox_Demo_02_01_2025_22_52_45.png?raw=true)

8. The custom rule triggers an alert regardless of the filename.

   ![Mimikatz alert triggered](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-02%20230354.png?raw=true)

---

### Step 6 — Connect Shuffle, VirusTotal, TheHive, and Email

1. Create a free account at [shuffler.io](https://shuffler.io), create a new workflow, and add a **Webhook trigger**. Copy the webhook URI.

   ![Shuffle webhook](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-02%20140830.png?raw=true)

2. Add the Shuffle integration to the Wazuh server and restart the manager:
   ```bash
   nano /var/ossec/etc/ossec.conf
   ```
   ```xml
   <integration>
     <name>shuffle</name>
     <hook_url>YOUR_WEBHOOK_URI</hook_url>
     <level>3</level>
     <alert_format>json</alert_format>
   </integration>
   ```
   ```bash
   systemctl restart wazuh-manager.service
   ```

   ![Wazuh Shuffle integration config](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20123212.png?raw=true)

3. Execute Mimikatz — events should appear in Shuffle.

   ![Shuffle events](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20130048.png?raw=true)

4. Add a **Regex node** to parse the SHA256 hash:
   - Input: `hashes` field
   - Regex: `SHA256=([A-Fa-f0-9]{64})`

   ![SHA256 regex node](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20131514.png?raw=true)

5. Add a **VirusTotal** app node — authenticate with your API key, set action to **Get a Hash Report**, and use the regex output as the ID.

   ![VirusTotal node](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20132319.png?raw=true)
   ![VirusTotal output](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20132940.png?raw=true)

6. In TheHive, create a new organisation and add two users: one analyst account and one SOAR account. Generate an API key for the SOAR account.

   ![TheHive organisation](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20143716.png?raw=true)
   ![TheHive users](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20152814.png?raw=true)
   ![TheHive analyst login](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20145010.png?raw=true)

7. In Shuffle, add a **TheHive** app node — authenticate with the SOAR API key and TheHive's public IP on port 9000.

   ![TheHive auth in Shuffle](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20145720.png?raw=true)

8. Set action to **Create Alert** and configure the JSON payload. On DigitalOcean, add a firewall rule to allow traffic on port 9000.

   ![Port 9000 firewall rule](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20154257.png?raw=true)

9. Rerun the workflow — an alert should appear in TheHive.

   ![TheHive alert created](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20161102.png?raw=true)
   ![TheHive alert detail](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20161032.png?raw=true)

10. Add an **Email** app node — configure the recipient, subject, and body with dynamic alert fields.

    ![Email node config](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20160513.png?raw=true)

11. Save and rerun the workflow — the SOC analyst should receive an email with the alert details.

    ![Email received](https://github.com/Samir-K9/SOC-Automation-Lab/blob/main/Screenshots/Screenshot%202025-01-03%20160848.png?raw=true)

---

## Skills Developed

- Designing and implementing automated SOC workflows with open-source tools
- Writing custom Wazuh detection rules resistant to evasion (filename renaming)
- Integrating SIEM, SOAR, and SIRP platforms into a unified pipeline
- Enriching IOCs with threat intelligence APIs (VirusTotal)
- Deploying and hardening cloud security infrastructure on DigitalOcean
- Managing multi-OS environments in a security operations context

---

## References

- [MyDFIR on YouTube](https://www.youtube.com/@MyDFIR) — original lab inspiration
- [Wazuh Documentation](https://documentation.wazuh.com)
- [TheHive Project](https://thehive-project.org)
- [Shuffle Documentation](https://shuffler.io/docs)
- [Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular)
