
# Linux Server Hardening Guide

*A Professional, Security-Engineered Hardening Framework*

---

## **Overview**

This repository provides a **comprehensive, industry-grade Linux hardening guide** aligned with:

* CIS Linux Benchmark
* NIST 800-123 Server Hardening Guide
* SOC/SIEM operational requirements
* DevSecOps best practices

The objective is to create a **secure, auditable, and minimal attack-surface Linux server** suitable for production.

---

# **1. Intention**

Linux servers ship with defaults optimized for usability—not security.
This guide aims to **reduce the attack surface**, strengthen authentication, and enforce secure operational standards.

### Goals:

* Minimize vulnerabilities
* Prevent unauthorized access
* Enforce least privileges
* Ensure reliable logging & monitoring
* Harden key services like SSH
* Achieve compliance with security frameworks

---

# **2. Objectives**

* Audit system users, services, and open ports
* Eliminate unnecessary accounts
* Restrict sudo rights
* Disable root login
* Enable SSH key-based authentication
* Apply updates & auto-security patches
* Harden firewall
* Secure file permissions
* Review logs & monitor system behavior

---

# **3. Hardening Methodology**

```
+---------------------+
| Phase 1: Discovery  |
+---------------------+
      |
      v
+-----------------------------+
| Phase 2: Reduce Attack Surface |
+-----------------------------+
      |
      v
+---------------------------+
| Phase 3: Strengthen Controls |
+---------------------------+
      |
      v
+---------------------------+
| Phase 4: Monitoring & Audit |
+---------------------------+
```

Four-phase hardening cycle ensures controlled and repeatable security posture.

---

# **4. Step-by-Step Hardening Guide**

---

## **4.1 Review System Settings (Users, Services, Ports)**

### List users & groups:

```bash
cat /etc/passwd
cat /etc/group
```

### Check last login of all users:

```bash
lastlog
```

### List running services:

```bash
systemctl --type=service --state=running
```

### List open ports:

```bash
ss -tulnp
```

**Purpose:** Detect unwanted users, stale accounts, misconfigured services, and exposed ports.

---

## **4.2 Remove Unused Accounts & Apply Least Privilege**

### List accounts with login shells:

```bash
awk -F: '($7 ~ /bash/)' /etc/passwd
```

### Lock unused accounts:

```bash
sudo usermod -L username
```

### Delete accounts:

```bash
sudo userdel -r username
```

### Restrict sudo access:

```bash
sudo visudo
```

Example minimal privilege rule:

```
user1 ALL=(ALL) /usr/bin/systemctl restart nginx
```

**Purpose:** Shrinks human-attack vectors & enforces controlled privilege elevation.

---

## **4.3 Disable Root Login & Enforce SSH Key Authentication**

Edit SSH config:

```bash
sudo nano /etc/ssh/sshd_config
```

Add or modify:

```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
```

Restart SSH:

```bash
sudo systemctl restart sshd
```

Generate SSH key:

```bash
ssh-keygen -t ed25519
ssh-copy-id user@server
```

**Purpose:** Replaces password-based identity with cryptographic identity.

---

## **4.4 Update System & Enable Automatic Security Updates**

```bash
sudo apt update && sudo apt upgrade -y
```

Enable auto-patching:

```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades
```

**Purpose:** Eliminates vulnerabilities by ensuring continuous patching.

---

## **4.5 Configure Firewall (UFW or iptables)**

---

### **UFW (Simplified Firewall)**

Allow essential services:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

Enable firewall:

```bash
sudo ufw enable
```

---

### **iptables (Advanced Control)**

Drop everything except essential ports:

```bash
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo netfilter-persistent save
```

**Purpose:** Restricts server exposure to the minimum required.

---

## **4.6 Stop & Disable Unnecessary Services**

List services:

```bash
systemctl list-unit-files --type=service
```

Stop unneeded services:

```bash
sudo systemctl stop bluetooth.service
sudo systemctl disable bluetooth.service
```

Mask insecure services:

```bash
sudo systemctl mask telnet
sudo systemctl mask rsh
sudo systemctl mask rexec
```

**Purpose:** Reduces exploitable daemon footprint.

---

## **4.7 Secure File Permissions**

### Critical system files:

```bash
sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow
```

### SSH directory:

```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

### Sensitive configs:

```bash
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 600 /etc/sudoers
```

**Purpose:** Prevent unauthorized access & tampering.

---

## **4.8 Log Review & Continuous Monitoring**

### Authentication logs:

```bash
sudo tail -f /var/log/auth.log
```

### System logs:

```bash
sudo journalctl -xe
```

### Privilege use:

```bash
grep sudo /var/log/auth.log
```

**Purpose:** Detect intrusion attempts, misconfigurations, and suspicious activity.

---

# **5. Expected Outcomes**

* Strong SSH security
* No root login
* Least-privilege enforcement
* Minimized services & ports
* Hardened configs and file permissions
* Continuous monitoring capability
* Production-grade security baseline

