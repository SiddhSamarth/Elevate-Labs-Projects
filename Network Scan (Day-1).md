# 🔍 Nmap Network Reconnaissance – Cyber Security Internship Task 1

---

## Objective

This project involved scanning the local network using **Nmap** to identify active hosts, enumerate open ports, and analyse services to understand network exposure.  
The task emphasises fundamental network reconnaissance and service identification practices essential to cybersecurity assessments.

---

## Skills Learned

- Conducting active network scanning using TCP SYN (`-sS`) technique.
- Analysing local IP ranges and interpreting Nmap scan output.
- Identifying common services based on open ports.
- Assessing security risks based on service exposure.
- Using **Wireshark** to capture and verify scan traffic at packet level.
- Documenting scan results and mapping services to known vulnerabilities.

---

## Tools Used

- **Nmap** – Port scanning and host discovery  
- **Ubuntu (CLI)** – Terminal-based scanning environment  
- **Wireshark** *(optional)* – Packet capture and deep inspection  
- **Markdown** – Reporting and documentation via GitHub

---

## Steps

**1. Find your IP and local subnet using:**

```bash
ip a
Then, grab the IP address and run a Nmap Scan on your Linux CLI

**sudo nmap -sS 192.XXX.XXX.0/24 -oN scan.txt**
```
![Screenshot 2025-06-23 193436](https://github.com/user-attachments/assets/d4e9156b-a3ea-45f0-bfbc-71f312858648)


### 📊 Analyze Scan Results

| Host IP (Masked)       | Open Port | Service      | State    | MAC Vendor |
|------------------------|-----------|--------------|----------|------------|
| 192.XXX.XXX.1          | 7070/tcp  | realserver   | open     | VMware     |
| 192.XXX.XXX.2 (Gateway)| 53/tcp    | domain (DNS) | open     | VMware     |
| 192.XXX.XXX.254        | —         | —            | filtered | VMware     |
| 192.XXX.XXX.129 (Host) | —         | —            | closed   | VMware     |

---

### 🔬 Validate with Wireshark *(Optional)*

Used **Wireshark** to inspect network activity during the Nmap scan for verification and traffic analysis.


#### 🔎 Filters Applied:

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.ack == 1
udp.port == 53 || tcp.port == 53
```
---

### 🧩 5. Investigate Services

Each open port was researched to understand its typical usage and potential exposure in a production or test environment.

| Port | Service     | Description                            |
|------|-------------|----------------------------------------|
| 7070 | RealServer  | Often associated with legacy streaming or proxy servers (e.g., Helix, RealNetworks) |
| 53   | DNS         | Standard service for domain name resolution. Commonly used by gateways or internal DNS servers |

> 📌 Understanding the nature of services helps evaluate whether their exposure is necessary or a potential vulnerability.

---

### 🔐 6. Risk Assessment

Risk evaluation of the discovered open ports was performed to identify potential attack vectors and propose defensive actions.

| Port | Risk Description                         | Mitigation Recommendation                    |
|------|-------------------------------------------|-----------------------------------------------|
| 7070 | Uncommon and often unmonitored; may host unused or insecure services | Block access externally via firewall; disable service if unnecessary |
| 53   | Publicly accessible DNS can be exploited in amplification attacks | Limit DNS to internal clients; monitor logs for abuse |

> ✅ Proactive mitigation helps reduce the attack surface and ensures only essential services are reachable.
