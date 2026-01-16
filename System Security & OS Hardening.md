# **Task 2: Explore User Accounts, Permissions, and Access Control**

## **Explanation**
This task focuses on identifying system users, groups, and understanding how Linux handles access control. These commands help enumerate user accounts and permission structures.

## **Code**
```bash
cat /etc/passwd         # Displays all user accounts and their details
cat /etc/group          # Shows all groups on the system
who                     # Shows currently logged-in users
w                       # Detailed info: logged-in users + their processes
groups <username>       # Lists all groups a user belongs to
```
### Code-Output
<img width="1058" height="836" alt="image" src="https://github.com/user-attachments/assets/f6515c02-d69e-45a1-be19-f4618d825e36" />

# **Task 2: Learn File Permissions (chmod, chown, ls -l)**

## **Explanation**
Linux uses a permission model to determine which users can read, write, or execute files.  
Understanding `chmod`, `chown`, and `ls -l` is essential for managing access control and maintaining a secure system.  
This task helps you interpret permission strings, modify access rights, and manage ownership.

## **Code**
```bash
ls -l                               # Displays file permissions, ownership, and metadata
chmod 644 file.txt                  # Sets owner: read/write; group & others: read-only
chmod 755 script.sh                 # Owner: full permissions; group/others: read + execute
chmod u+x script.sh                 # Adds execute permission for the file owner
chmod go-w config.conf              # Removes write permission from group and others
sudo chown user:group file.txt      # Changes ownership of a file to a specific user/group
```
<img width="1058" height="836" alt="image" src="https://github.com/user-attachments/assets/0f64e690-cff9-49a7-909d-637f7a27f870" />
# **Task 3: Understand Administrator vs Standard User Privileges**

## **Explanation**
Linux enforces a strict privilege model to ensure system security.  
Standard users have limited access and can perform only non-destructive operations, while administrators (root users) have full control over the system.

The `sudo` mechanism allows privileged commands to be executed securely, preventing accidental system-wide changes.  
This task helps you understand how to check privileges, escalate privileges safely, and manage administrative access.

---

## **Code**
```bash
sudo -l                             # Lists all commands the current user is allowed to run with sudo privileges
sudo su                             # Switches to the root account (administrator mode)
sudo <command>                      # Executes a single command with elevated (root) privileges
sudo usermod -aG sudo <username>    # Adds a user to the sudo group to grant administrative rights
```
<img width="1058" height="836" alt="image" src="https://github.com/user-attachments/assets/e57e5d71-1c84-4b4e-b397-fac55dc1ee3d" />

# **Task 4: Enable Firewall (UFW in Linux)**

## **Explanation**
A firewall is a critical security control used to monitor and filter incoming and outgoing network traffic.  
It helps protect the system from unauthorized access by allowing only trusted services and blocking unnecessary ports.

UFW (Uncomplicated Firewall) provides a simple interface to manage firewall rules in Linux.  
Enabling and configuring UFW significantly reduces the system’s attack surface.

---

## **Code**
```bash
sudo ufw enable                     # Enables and activates the UFW firewall
sudo ufw allow ssh                  # Allows SSH traffic (default port 22) for remote access
sudo ufw allow 80/tcp               # Allows HTTP traffic (port 80)
sudo ufw allow 443/tcp              # Allows HTTPS traffic (port 443)
sudo ufw status verbose             # Displays firewall status and active rules in detail
```
<img width="1058" height="572" alt="image" src="https://github.com/user-attachments/assets/84cc7203-114f-41f8-86f9-c63e79a7c154" />

# **Task 5: Identify Running Processes and Services**

## **Explanation**
Processes and services represent programs and background tasks currently running on the system.  
Monitoring them is essential for identifying suspicious activity, resource abuse, and unnecessary services that may increase the attack surface.

This task focuses on listing active processes, viewing system resource usage in real time, identifying running services, and checking open network ports.

---

## **Code**
```bash
ps aux                              # Displays all running processes with user, PID, and resource usage
top                                 # Shows real-time CPU and memory usage of active processes
htop                                # Enhanced interactive process monitoring tool
systemctl list-units --type=service # Lists all active system services managed by systemd
sudo ss -tulnp                      # Displays listening ports and the services bound to them
```
<img width="1058" height="740" alt="image" src="https://github.com/user-attachments/assets/bf188b1b-9405-41f1-8981-077128d0dbf1" />

# **Task 6: Disable Unnecessary Services**

## **Explanation**
Every running service increases the system’s attack surface.  
Disabling unused or unwanted services helps reduce potential entry points for attackers, improves performance, and strengthens overall system security.

Linux uses **systemd** to manage services.  
Stopping a service halts it temporarily, disabling it prevents it from starting on boot, and masking it completely blocks it from being triggered manually or automatically.

---

## **Code**
```bash
sudo systemctl stop <service>       # Stops the service immediately (temporary)
sudo systemctl disable <service>    # Disables the service from starting at system boot
sudo systemctl mask <service>       # Completely prevents the service from being started
```
<img width="1058" height="740" alt="image" src="https://github.com/user-attachments/assets/ac50990d-1280-45ad-9a06-68af4c22cdfb" />

# **Task 7: Document Best OS Hardening Practices**

## **Explanation**
OS hardening is the process of securing an operating system by reducing its attack surface, enforcing strict access control, disabling unnecessary services, and implementing security best practices.

A hardened system is more resilient to cyber attacks, unauthorized access, privilege escalation, and malware infections.  
These practices are widely used in enterprise environments, SOC operations, and secure server deployments.

---

## **Checklist of OS Hardening Best Practices**
```md
- Enforce strong passwords and multi-factor authentication (MFA)
- Apply the principle of least privilege for all users
- Limit the number of users with sudo/admin privileges
- Disable root login for SSH to prevent direct unauthorized access
- Configure the firewall to allow only required ports/services
- Remove unnecessary software and disable unused services/daemons
- Regularly update the OS, installed packages, and security patches
- Set strict file permissions for sensitive files (e.g., /etc/shadow, SSH configs)
- Use SELinux or AppArmor for mandatory access control
- Enable and monitor system logs using syslog, journald, or auditd
- Use secure communication protocols (SSH, HTTPS) instead of outdated ones
- Restrict open ports and public-facing services
- Implement automatic updates or scheduled patch management
- Backup critical data regularly and test recovery procedures
- Protect system against brute-force attacks (fail2ban, ssh rate limiting)
- Monitor system performance, resource usage, and suspicious processes
```


