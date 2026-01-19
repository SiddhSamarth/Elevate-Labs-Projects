# **Task 8: Basic Networking & Wireshark Traffic Analysis**

## **Explanation**
This task focuses on understanding core networking concepts and analyzing real network traffic using Wireshark.  
By capturing and inspecting packets, we can observe how data flows across a network, which protocols are used, which ports are involved, and whether the communication is secure or vulnerable.

This task develops foundational skills required for network monitoring, intrusion detection, and SOC analysis.

---

## **1. Basic Networking Concepts**

### **IP Address**
An IP address uniquely identifies a device on a network.  
It enables routing of data between devices.

- IPv4 example: `192.168.1.10`
- IPv6 example: `fe80::1`

### **MAC Address**
A MAC address is a hardware-level identifier assigned to a network interface.  
It operates at Layer 2 (Data Link layer).

- Example: `08:00:27:ab:cd:ef`

### **DNS (Domain Name System)**
DNS resolves human-readable domain names into IP addresses.

- Protocol: UDP (mostly)
- Default Port: **53**
- Example: `google.com → 142.250.xxx.xxx`

### **TCP vs UDP**
- **TCP (Transmission Control Protocol)**  
  - Connection-oriented  
  - Reliable, ordered delivery  
  - Used by HTTP, HTTPS, SSH  
  - Ports: 80, 443, 22

- **UDP (User Datagram Protocol)**  
  - Connectionless  
  - Faster, less reliable  
  - Used by DNS, streaming, VoIP  
  - Ports: 53, 123

---

## **2. Network Configuration Discovery**

## **Explanation**
Before capturing traffic, it is important to understand the system’s network configuration, including IP address, gateway, and DNS servers.

## **Code**
```bash
ip a                     # Displays IP address, MAC address, and interfaces
ip route                 # Shows default gateway and routing table
cat /etc/resolv.conf     # Displays configured DNS servers
```
# **Task 3: Understand Administrator vs Standard User Privileges**

## **Explanation**
Modern operating systems follow the principle of **privilege separation** to reduce security risks.  
A **standard user** operates with limited permissions, while an **administrator (root)** has full control over the system.

Linux uses the `sudo` mechanism to temporarily grant elevated privileges.  
This reduces the risk of accidental system damage and limits the impact of compromised user accounts.

Understanding this distinction is critical for system hardening, access control, and preventing privilege escalation attacks.

---

## **Privilege Levels**

### **Standard User**
- Limited access to system files
- Cannot install system-wide software
- Cannot start/stop critical services
- Lower security risk if compromised

### **Administrator (Root)**
- Full access to system resources
- Can modify system configuration
- Can manage users, services, and firewall rules
- High-value target for attackers

---

## **Security Relevance**
- Excessive admin privileges increase attack impact
- Malware running as root can fully compromise the system
- Least Privilege Principle (LPP) minimizes damage
- Controlled privilege escalation improves auditability

---

## **Code**
```bash
sudo -l                             # Lists commands the current user is allowed to run with sudo
sudo su                             # Switches to the root (administrator) account
sudo <command>                      # Executes a single command with elevated privileges
sudo usermod -aG sudo <username>    # Grants admin privileges by adding user to sudo group
```
## Security Observations
- Check how many users have sudo access
- Avoid using root account directly
- Prefer sudo for command-level privilege escalation
- Remove unnecessary users from sudo group

# **Task 4: Enable Firewall (UFW in Linux)**

## **Explanation**
A firewall is a core security control that filters incoming and outgoing network traffic.  
Linux systems often use **UFW (Uncomplicated Firewall)** as a simplified interface for configuring `iptables`.

Firewalls help enforce **network security boundaries**, block unauthorized access, and prevent attackers from probing open ports.  
Enabling and configuring UFW is a critical step in OS hardening.

---

## **Firewall Basics**

### **What a Firewall Does**
- Blocks unwanted inbound traffic  
- Allows only approved services  
- Monitors network flows  
- Prevents unauthorized access attempts  

### **Common Ports and Services**
| Service | Protocol | Port | Description |
|---------|----------|------|-------------|
| SSH     | TCP      | 22   | Secure remote login |
| HTTP    | TCP      | 80   | Unencrypted web traffic |
| HTTPS   | TCP      | 443  | Encrypted web traffic |
| DNS     | UDP/TCP  | 53   | Domain name resolution |

---

## **Security Relevance**
- Closing unused ports reduces attack surface  
- Blocks brute force attempts on SSH  
- Prevents scanning tools like Nmap from discovering services  
- Helps stop unauthorized lateral movement inside a network  

---

## **Code**
```bash
sudo ufw enable                     # Activates the firewall protection
sudo ufw allow ssh                  # Allows SSH access (TCP port 22)
sudo ufw allow 80/tcp               # Allows HTTP traffic (port 80)
sudo ufw allow 443/tcp              # Allows HTTPS traffic (port 443)
sudo ufw status verbose             # Displays current firewall rules and status
```
## **Security Relevance**
- Check if unnecessary ports are open
- Ensure SSH (22) is allowed before enabling firewall, or risk locking yourself out
- Avoid allowing insecure services such as Telnet (23) or FTP (21)
- Verify UFW default policies (deny incoming, allow outgoing)

# **Task 5: Identify Running Processes and Services**

## **Explanation**
Every operating system runs multiple processes and background services.  
Monitoring them is essential for detecting suspicious activity, understanding resource usage, and securing the system.

Attackers often try to:
- Run malicious processes in the background  
- Bind malware to open ports  
- Masquerade as legitimate services  
- Maintain persistence by enabling unauthorized services  

Therefore, being able to list, filter, and analyze system processes is a key SOC and system-hardening skill.

---

## **What You Are Checking**

### **Processes**
Programs currently running on the system.

### **Services (Daemons)**
Background tasks managed by **systemd** that start automatically or manually.

### **Ports & Network Bindings**
Which services are listening for incoming connections.

### **Key Questions**
- Are there unknown processes running?
- Are services listening on unexpected ports?
- Are CPU/memory spikes caused by malicious programs?
- Is any outdated or unsafe protocol running?

---

## **Common Ports to Pay Attention To**
| Port | Protocol | Service | Security Risk |
|------|----------|---------|----------------|
| 22   | TCP      | SSH     | Brute-force attacks, weak SSH config |
| 80   | TCP      | HTTP    | Plain-text traffic, MITM attacks |
| 443  | TCP      | HTTPS   | Secure encrypted traffic |
| 21   | TCP      | FTP     | Insecure, plain-text credentials |
| 23   | TCP      | Telnet  | Highly insecure, deprecated |
| 3306 | TCP      | MySQL   | Sensitive DB exposure if open |
| 53   | UDP/TCP  | DNS     | DNS poisoning, tunneling |

---

## **Code**
```bash
ps aux                              # Lists all running processes with user, PID, memory & CPU usage
top                                 # Real-time monitoring of processes, resource consumption
htop                                # Advanced interactive view (color-coded, easier to navigate)
systemctl list-units --type=service # Shows all active systemd services currently running
sudo ss -tulnp                      # Lists open ports + which process/service is attached to them
```
## Security Relevance
- Unknown processes may indicate malware or unauthorized tools
- Services listening on open ports can be exploited if misconfigured
- High CPU or memory usage may signal cryptomining or botnet activity
- Outdated or insecure services (FTP, Telnet) should be disabled immediately
- DNS tunneling or suspicious outbound connections may indicate compromise


# **Task 6: Disable Unnecessary Services**

## **Explanation**
Every running service increases the overall attack surface of a system.  
If a service is not required for normal system functionality, it becomes an unnecessary security risk.

Attackers commonly target:
- Outdated or vulnerable services  
- Forgotten services running on open ports  
- Misconfigured daemons exposing sensitive interfaces  
- Background services that can be abused for privilege escalation  

Disabling unused services ensures the system remains lean, secure, and resistant to exploitation.  
On Linux systems, services are managed using **systemd**, which allows services to be stopped, disabled at startup, or completely masked to prevent execution.

---

## **Why This Matters (Security Context)**

### **1. Unknown Processes and Services**
Unknown or suspicious services may indicate:
- Malware running persistently  
- Unauthorized remote-access backdoors  
- Cryptomining bots consuming system resources  

### **2. Open Ports as Attack Entry Points**
Services listening on open ports can be directly exploited if misconfigured or unpatched.

**Examples:**
- **FTP (Port 21)** → Plain-text credentials  
- **Telnet (Port 23)** → No encryption, extremely insecure  
- **MySQL (Port 3306)** → Database exposure if publicly accessible  

### **3. High Resource Usage**
Unusual CPU or memory consumption may indicate:
- Cryptomining malware  
- Botnet activity  
- Rogue or hijacked processes  

### **4. Outdated or Deprecated Services**
Certain services are inherently insecure and should not be used:
- **Telnet (Port 23)** – No encryption  
- **FTP (Port 21)** – Credentials sent in clear text  
- **rlogin / rsh** – Deprecated remote shell services  

### **5. DNS Tunneling and Suspicious Outbound Traffic**
DNS (Port 53) can be abused to:
- Exfiltrate sensitive data  
- Maintain command-and-control (C2) communication  

---

## **Code**

### **Service Management Commands**
```bash
sudo systemctl stop <service>       # Stops a running service temporarily
sudo systemctl disable <service>    # Prevents the service from starting on boot
sudo systemctl mask <service>       # Completely blocks the service from being started
```
# **Task 6: Disable Unnecessary Services**

## **Explanation**
Every running service increases the overall attack surface of a system.  
If a service is not required for normal system functionality, it becomes an unnecessary security risk.

Attackers commonly target:
- Outdated or vulnerable services  
- Forgotten services running on open ports  
- Misconfigured daemons exposing sensitive interfaces  
- Background services that can be abused for privilege escalation  

Disabling unused services ensures the system remains lean, secure, and resistant to exploitation.  
On Linux systems, services are managed using **systemd**, which allows services to be stopped, disabled at startup, or completely masked to prevent execution.

---

## **Why This Matters (Security Context)**

### **1. Unknown Processes and Services**
Unknown or suspicious services may indicate:
- Malware running persistently  
- Unauthorized remote-access backdoors  
- Cryptomining bots consuming system resources  

### **2. Open Ports as Attack Entry Points**
Services listening on open ports can be directly exploited if misconfigured or unpatched.

**Examples:**
- **FTP (Port 21)** → Plain-text credentials  
- **Telnet (Port 23)** → No encryption, extremely insecure  
- **MySQL (Port 3306)** → Database exposure if publicly accessible  

### **3. High Resource Usage**
Unusual CPU or memory consumption may indicate:
- Cryptomining malware  
- Botnet activity  
- Rogue or hijacked processes  

### **4. Outdated or Deprecated Services**
Certain services are inherently insecure and should not be used:
- **Telnet (Port 23)** – No encryption  
- **FTP (Port 21)** – Credentials sent in clear text  
- **rlogin / rsh** – Deprecated remote shell services  

### **5. DNS Tunneling and Suspicious Outbound Traffic**
DNS (Port 53) can be abused to:
- Exfiltrate sensitive data  
- Maintain command-and-control (C2) communication  

---

## **Code**

### **Service Management Commands**
```bash
sudo systemctl stop <service>       # Stops a running service temporarily
sudo systemctl disable <service>    # Prevents the service from starting on boot
sudo systemctl mask <service>       # Completely blocks the service from being started
```

## Examoles
```bash
sudo systemctl stop bluetooth       # Stop Bluetooth service if unused
sudo systemctl disable cups         # Disable printer service on servers
sudo systemctl mask telnet          # Telnet is insecure; block completely
sudo systemctl disable rpcbind      # Often unnecessary; reduces attack surface
```
## Security Observations
- Unknown processes may indicate malware or unauthorized tools
- Services listening on open ports can be exploited if misconfigured
- High CPU or memory usage may signal cryptomining or botnet activity
- Outdated or insecure services (FTP, Telnet) should be disabled immediately
- DNS tunneling or suspicious outbound connections may indicate system compromise

# **Task 7: Document Best OS Hardening Practices**

## **Explanation**
OS hardening is the process of securing an operating system by reducing vulnerabilities, enforcing strict access controls, disabling unnecessary components, and implementing security best practices.  
A hardened system is significantly more resistant to malware, privilege escalation, data breaches, and unauthorized remote access.

This task focuses on understanding essential OS hardening techniques used in enterprise security, SOC operations, penetration testing, and server administration.

---

## **Why OS Hardening Is Important (Security Context)**

### **1. Reduces Attack Surface**
By disabling unused services, removing unnecessary packages, and closing open ports, you reduce the number of entry points available to attackers.

### **2. Prevents Unauthorized Access**
Strong authentication, limited privileges, and secure configurations stop attackers from easily gaining control over the system.

### **3. Protects Sensitive Files**
Misconfigured permissions can expose critical files like:
- `/etc/passwd`
- `/etc/shadow`
- SSH keys
- Application secrets

Securing them prevents credential theft and privilege escalation.

### **4. Enforces System Integrity**
Proper logging, auditing, and MAC (Mandatory Access Control) help detect and prevent malicious activity.

### **5. Ensures Secure Communication**
Using secure protocols (SSH, HTTPS) prevents man-in-the-middle attacks and credential interception.

---

## **OS Hardening Best Practices (Full Checklist)**
Authentication & Access Control:
- Enforce strong passwords and enable multi-factor authentication (MFA)
- Disable root login for SSH to prevent direct system compromise
- Apply the Principle of Least Privilege (PoLP) to all users
- Limit sudo/admin rights to essential personnel only

Service & Process Hardening:
- Disable or remove unnecessary services (FTP, Telnet, rlogin, rsh)
- Monitor high CPU/memory processes to detect cryptomining or malware
- Stop and disable services not required for system operation

Network Hardening:
- Enable and configure a firewall (UFW/iptables)
- Allow only required ports and deny the rest
- Disable unused network interfaces
- Use SSH instead of Telnet; use SFTP/SCP instead of FTP

File System & Permission Security:
- Secure sensitive files (e.g., /etc/shadow, /etc/ssh/ssh_config)
- Set least-privilege file permissions (chmod, chown)
- Mount partitions with security options (noexec, nodev, nosuid)

System Updates & Patch Management:
- Regularly update OS packages and security patches
- Enable automatic updates where possible
- Remove outdated or vulnerable software

Logging & Monitoring:
- Enable system logging using journald or syslog
- Enable auditd for tracking sensitive activities
- Monitor suspicious outbound traffic (possible DNS tunneling)
- Inspect logs for brute-force, scanning, or unauthorized access attempts

Secure Communication:
- Use HTTPS instead of HTTP
- Use SSH (port 22) with key-based authentication
- Disable insecure protocols and weak ciphers

Backup & Recovery:
- Regularly back up critical data
- Test restoration procedures
- Store backups securely and encrypt them

General Hardening:
- Disable USB autorun (prevents malware via USB)
- Disable guest accounts
- Install anti-malware or integrity-checking tools (e.g., chkrootkit, rkhunter)
# **Task 8: Basic Networking & Wireshark Traffic Analysis**

## **Explanation**
This task focuses on understanding fundamental networking concepts and performing hands-on traffic analysis using Wireshark.  
You will learn how IP, MAC, DNS, TCP, and UDP work, how packets flow through a network, and how to inspect real traffic at the protocol level.  
You will also analyze plaintext vs encrypted traffic, observe TCP handshakes, examine DNS queries, and save packet captures.

These skills are essential for SOC analysts, network defenders, incident responders, and penetration testers.

---

## **Section 1: Basic Networking Concepts**

### **IP Address (Internet Protocol)**
Identifies a host on the network.  
Used for routing data between devices.  
- IPv4 example: `192.168.1.10`  
- IPv6 example: `fe80::1`

### **MAC Address (Media Access Control)**
A unique hardware-level identifier (Layer 2).  
Used by switches to forward frames.  
- Example: `08:00:27:ab:cd:ef`

### **DNS (Domain Name System)**
Converts domain names into IP addresses.  
- Protocol: UDP/TCP  
- Port: **53**  
- Example: `example.com → 93.184.216.34`

### **TCP vs UDP**
| Protocol | Type | Reliability | Use Cases | Common Ports |
|----------|------|-------------|-----------|---------------|
| **TCP** | Connection-oriented | Reliable | HTTPS, SSH, FTP | 80, 443, 22 |
| **UDP** | Connectionless | Fast, no guarantee | DNS, VoIP, Streaming | 53, 123, 500 |

---

## **Section 2: Network Configuration Discovery**

### **Explanation**
Before capturing packets, you must identify your IP address, DNS, gateway, and interface details.

### **Code**
```bash
ip a                     # Shows IP, MAC, interface details
ip route                 # Shows routing table and default gateway
cat /etc/resolv.conf     # Displays DNS resolver configuration
```
# Section 3: Install and Launch Wireshark

## Explanation
Wireshark is a packet capture and analysis tool used across SOC, IR, and pentesting.

## Code
```bash
sudo apt install wireshark -y # Install Wireshark
sudo usermod -aG wireshark $USER # Allow non-root packet capture
wireshark # Launch GUI
```

# Section 4: Filter Packets by Protocol

## Explanation
Filters help isolate specific traffic types for analysis.

## Wireshark Filters
dns # Port 53 DNS queries/responses
tcp # TCP protocol traffic
ehttps # Port 443, encrypted TLS traffic
tls # For TLS/SSL traffic (alternative to https)
http # Port 80, plaintext web traffic
iip.addr== # Traffic sent from/to a specific IP address

# Security Notes
- HTTP can expose logins and cookies.
- HTTPS hides content but metadata remains visible.
- DNS reveals browsing habits.
- TCP flags can show scanning activities like SYN floods or Xmas scans.

# Section 5: Observe TCP Three-Way Handshake

## Explanation
TCP connections start with:
- **SYN** – Client requests connection
- **SYN-ACK** – Server responds with acknowledgment
- **ACK** – Connection established

## Security Angle
defense considerations include:
- High SYN traffic may signal a DoS attack.
- Incomplete handshakes may indicate scanning tools such as Nmap.
- Unexpected remote IPs initiating connections may be malicious.

# Section 6: Identify Plaintext vs Encrypted Traffic

## Explanation
the ability to inspect traffic helps determine whether data is exposed or protected.
 
### Plaintext (Insecure)
- Protocol: HTTP 
- Port: 80 
- Credentials visible 
- Vulnerable to MITM attacks 
 
### Encrypted (Secure)
- Protocol: HTTPS (TLS) 
- Port: 443 
- Protects confidentiality & integrity 
 
### Vulnerability Examples
detecting issues such as:
s sniffing HTTP credentials,
session hijacking,
cookie stealing,
traffic injection or manipulation.

# Section 7: Capture and Analyze DNS Queries

## Explanation
dns queries reveal domain lookups and communication patterns.
 
dns Details:
p rotocol: UDP/TCP,
p ort: 53,
displays domain → IP relationships.
 
nSecurity Risks:
dNS tunneling for data exfiltration,
m malware C2 traffic using DNS,
suspicious or malformed DNS packets.
 
best practices include monitoring for anomalies in DNS activity.
 
defense strategies involve filtering suspicious DNS requests and inspecting payloads for malicious indicators.
 
before deploying any security controls, ensure proper logging of DNS activity for forensic analysis later on.""}
