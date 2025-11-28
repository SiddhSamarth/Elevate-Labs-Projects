# Basic Firewall Configuration using UFW on Kali Linux

##  Objective
Configure and test basic firewall rules using **UFW (Uncomplicated Firewall)** on Kali Linux. The goal is to block unsafe ports like **Telnet (23)**, allow secure services like **SSH (22)**, and verify the rules through hands-on testing.

---

##  Theoretical Knowledge

A **firewall** is a system that monitors and filters incoming/outgoing network traffic based on predefined security rules. UFW is a host-based firewall that provides a simple command-line interface to manage complex `iptables` under the hood.

- **Telnet (port 23)** is insecure and must be blocked.
- **SSH (port 22)** is secure and commonly used for remote administration.
- UFW allows you to quickly **enable**, **block**, **allow**, and **verify** firewall rules.

---

## 🛠 Tools Used

| Tool        | Purpose                        |
|-------------|--------------------------------|
| UFW         | Firewall configuration utility |
| OpenSSH     | Enable secure login for testing|
| Telnet      | Used to test blocked ports     |
| Kali Linux  | OS used for configuration      |

---

## Firewall Configuration & Testing

### Step 1: Install & Enable UFW
```bash
sudo apt update
sudo apt install ufw -y
sudo ufw enable
```
![image](https://github.com/user-attachments/assets/ac54c151-e2b2-4bf6-b181-fda0bb028e87)



##  Step 2: Block Insecure Telnet Port (Port 23)

###  Theoretical Background:
**Telnet** is a legacy protocol that operates on **port 23** and allows users to remotely access and manage devices. However, it transmits data in **plain text**, including sensitive login credentials — making it highly insecure and vulnerable to interception.

**Why block it?**
- It’s rarely needed in modern systems.
- It poses a serious **security risk** if left open.
- Blocking it hardens your system against unauthorized access.

### 💻 Command:
```bash
sudo ufw deny 23
```
![image](https://github.com/user-attachments/assets/06bbc551-6faf-471e-bf1a-66c821e23e80)


# Step 3 – Allow Secure SSH Access (Port 22)

---

## 🔐 Objective:
To allow incoming SSH connections on **port 22** using UFW so that secure remote access to the system is possible.

---

## 📖 Theoretical Background:

**SSH (Secure Shell)** is a cryptographic network protocol used for secure remote login and command execution. It runs on **port 22** by default and encrypts all traffic, protecting against eavesdropping, connection hijacking, and other network attacks.

### Why is SSH important?
- Provides secure access to headless systems (without a GUI).
- Essential for managing remote servers or VMs.
- Used extensively in cybersecurity, system administration, and ethical hacking.

---

## 💡 Explanation:
By default, UFW denies all incoming connections. To allow remote administration through SSH, we need to explicitly **open port 22**. This ensures the system remains accessible over the network while other ports are protected.

---

## Command to Allow SSH:
```bash
sudo ufw allow 22
```
![image](https://github.com/user-attachments/assets/47d93c26-8e86-418e-9c6a-84eec723ad8a)



# Step 4 – View Active UFW Rules (Firewall Status)

---

## Objective:
To list all active firewall rules applied via **UFW (Uncomplicated Firewall)** in order to verify that the correct security policies are in place.

---

## Theoretical Background:

After applying firewall rules, it is essential to **audit** and **verify** them. UFW provides a simple way to list all current rules, including:

- **Port numbers**
- **Protocols**
- **Allow/deny actions**
- **Assigned rule numbers**

These rule numbers are important for **managing and deleting** specific rules later.

---

##  Explanation:

UFW applies rules in the order they're added. By using `ufw status numbered`, you:

- Get a **numbered list** of all current firewall rules.
- Can reference rule numbers when deleting/modifying them.
- Quickly confirm that your intended configuration (e.g., blocking port 23, allowing port 22) has been applied successfully.

---

## Command to List Firewall Rules:
```bash
sudo ufw status numbered
```
![image](https://github.com/user-attachments/assets/12e043af-0373-41cc-bc95-f648282ad1a0)


# Step 5 – Testing the Firewall Rules (Telnet Block & SSH Allow)

---

## Objective:
To verify that the firewall rules configured in the previous steps are working correctly:
- **Telnet (port 23)** should be **blocked**.
- **SSH (port 22)** should be **allowed**.

---

## 📖 Theoretical Background:

### 🔹 Telnet (Port 23)
Telnet is an insecure, legacy protocol used for remote terminal access. Blocking Telnet ensures that unauthorised and unencrypted access attempts are rejected.

### 🔹 SSH (Port 22)
SSH is a secure protocol that allows encrypted remote access. Allowing this port ensures secure connectivity for administrative purposes.

Proper testing of these ports verifies that UFW rules are enforced and functioning as expected.

---

##  Test 1: Blocked Telnet (Port 23)

### Command:
```bash
telnet 127.0.0.1 23
```
# Step 6 – Cleanup and Conclusion

---

## Objective:
To restore the firewall to its original or cleaner state after testing, by removing temporary test rules (e.g., the Telnet block) and concluding the task with a reflection on what was learned.

---

## Optional Cleanup

After confirming that your firewall rules work correctly, it's a good practice to either remove specific test rules or reset the firewall to its default state.

---

###  Delete Telnet Block Rule (Port 23)

If you want to remove just the Telnet block:

```bash
sudo ufw delete deny 23
```

# Final Thoughts

- Enabled the firewall
- Applied rule-based traffic filtering
- Blocked insecure ports (Telnet)
- Allowed secure services (SSH)
- Verified rule behaviour through hands-on testing
- Optionally cleaned up the firewall configuration

---

## 🧠 Key Learnings

| Concept                | Summary                                                             |
|------------------------|---------------------------------------------------------------------|
| Host-based Firewall    | UFW provides simple CLI control over iptables                      |
| Port-based Filtering   | Traffic can be allowed/denied based on port or service             |
| Secure Access          | Only secure and required ports should be left open                 |
| Testing & Verification | Essential to confirm that firewall behavior matches intent         |
| System Hardening       | Firewalls are a core layer of modern cybersecurity defense         |

---

# 📖How Firewalls Filter Network Traffic (Summary)
## 🔥 What Does a Firewall Do?

A firewall acts as a **gatekeeper** between your device and the network. It uses defined rules to determine whether to **allow or deny traffic** based on several criteria:

- **Port Numbers** – e.g., `22` for SSH, `23` for Telnet  
- **IP Addresses** – Source and Destination IPs  
- **Protocol Type** – TCP, UDP, ICMP  
- **Traffic Direction** – Incoming or Outgoing  

---

## 🔄 Traffic Flow Logic (UFW)

- By default, **UFW denies all incoming traffic** unless explicitly allowed.
- When a network packet reaches your system, **UFW checks the rules from top to bottom**.
- The **first matching rule** is applied — no further rules are checked for that packet.
- This **top-down rule evaluation** ensures predictable and secure behavior.

---

## 🔐 Real-World Impact

Using a properly configured firewall like UFW:

- 🚫 **Prevents unauthorised access** (e.g., port scans, Telnet exploits)  
- 🛡️ **Reduces your system's attack surface**  
- 🔒 **Enforces the principle of least privilege** — only essential services are accessible  

---

