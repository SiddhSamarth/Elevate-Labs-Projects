# Elevate Labs Cybersecurity Practical Laboratory Portfolio

Documentation and lab notes for 20 hands-on security exercises completed during the Elevate Labs training program. The exercises cover network reconnaissance, host hardening, traffic analysis, email header forensics, vulnerability assessment, and web exploitation in virtualized lab environments.

---

## Program & Exercise Provenance

These modules document laboratory coursework and practical exercises completed as part of the Elevate Labs training curriculum. Exercises utilize open-source security tools (Nmap, Wireshark, UFW, OpenSSL) against simulated targets. Referenced walkthrough materials and screenshots in Day-3 are attributed to their original source ([@laaaaaarry](https://github.com/laaaaaarry/Vulnerability-Management)).

---

## Laboratory Index & Master Table of Contents

The 20 modules and project artifacts are organized across 5 core cybersecurity domains:

### 1. Network Reconnaissance & Protocol Analysis
| Lab Document | Tools Used | Key Focus & Methodology |
| :--- | :--- | :--- |
| **[Network Scan (Day-1.md)](./Network%20Scan%20(Day-1).md)** | Nmap | Host discovery, SYN stealth scanning (`-sS`), port enumeration, service version detection (`-sV`). |
| **[Network Vulnerability Scanning.md](./Network%20Vulnerability%20Scanning%20.md)** | Nmap NSE, Nessus | Automated script scanning using Nmap Scripting Engine (NSE) to detect misconfigurations and unpatched services. |
| **[Networking & Wireshark Traffic Analysis.md](./Networking%20&%20Wireshark%20Traffic%20Analysis.md)** | Wireshark, Tshark | Packet capture inspection, TCP 3-way handshake analysis, Berkeley Packet Filters (BPF), and protocol dissection. |
| **[VPN Authenticity Verification.md](./VPN%20Authenticity%20Verification.md)** | OpenVPN, Wireshark | Tunnelling protocol evaluation, handshake encryption, IP/DNS leak testing, and cryptographic cipher verification. |

### 2. Threat Detection, Phishing & Digital Forensics
| Lab Document | Tools Used | Key Focus & Methodology |
| :--- | :--- | :--- |
| **[Email Phishing Analysis (Day-2.md)](./Email%20Phishing%20Analysis%20(Day-2).md)** | Text Parsers, MXToolbox | Forensic deconstruction of raw RFC 822 email headers, tracking Received hops, and validating SPF/DKIM/DMARC records. |
| **[sample1.eml](./sample1.eml)** | Raw MIME / EML | authoritative sample email artifact used for phishing header forensics and artifact extraction. |
| **[Phishing Attack Simulation & Detection.md](./Phishing%20Attack%20Simulation%20&%20Detection.md)** | GoPhish / CLI Tools | Simulated social engineering scenarios, credential-harvesting landing pages, and email gateway filtering rules. |
| **[Incident Response & Security Breach Simulation.md](./Incident%20Response%20&%20Security%20Breach%20Simulation.md)** | Netstat, Syslog, Bash | SANS PICERL framework simulation: rogue process identification, network socket isolation, and containment playbooks. |
| **[Log Monitoring & Analysis.md](./Log%20Monitoring%20&%20Analysis.md)** | Linux Syslog, Grep, Awk | Auditing `/var/log/auth.log`, detecting failed SSH login spikes, and parsing HTTP access logs for anomaly signatures. |

### 3. Defensive Security, Hardening & Cryptography
| Lab Document | Tools Used | Key Focus & Methodology |
| :--- | :--- | :--- |
| **[Basic Firewall Configuration (Day-4.md)](./Basic%20Firewall%20Configuration%20(Day-4).md)** | UFW, iptables | Host firewall rule construction, default-deny ingress policies, port restriction, and connection rate limiting. |
| **[Linux Server Hardening & Secure Configuration.md](./Linux%20Server%20Hardening%20&%20Secure%20Configuration.md)** | OpenSSH, Sudoers | `sshd_config` auditing (PermitRootLogin no, PubkeyAuthentication), Sudoers privilege audits, and permission lockouts. |
| **[Cryptography Fundamentals.md](./Cryptography%20Fundamentals.md)** | OpenSSL, Hashcat | Symmetric/asymmetric encryption principles, SHA-256 integrity hashing, and PKI digital certificate structures. |
| **[Password Security & Authentication Analysis.md](./Password%20Security%20&%20Authentication%20Analysis.md)** | John the Ripper, Hydra | Password hash cracking analysis, dictionary attack demonstrations, and brute-force resistance evaluations. |
| **[Password Strength Evolution.md](./Password%20Strength%20Evolution.md)** | Entropy Evaluators | Comparative analysis of entropy requirements, dictionary defenses, and modern NIST SP 800-63B guidelines. |

### 4. Web Application & API Security
| Lab Document | Tools Used | Key Focus & Methodology |
| :--- | :--- | :--- |
| **[SQL Injection Practical Exploitation.md](./SQL%20Injection%20Practical%20Exploitation.md)** | DVWA, SQLMap | In-band, boolean-based, and union-based SQL injection exploitation, database dumping, and parameterized query remediation. |
| **[Secure API Testing & Authorization Validation.md](./Secure%20API%20Testing%20&%20Authorization%20Validation.md)** | Postman, cURL | REST API endpoint assessment, Broken Object Level Authorization (BOLA/IDOR) testing, and JWT token validation. |
| **[Browser Extensions Evaluation.md](./Browser%20Extensions%20Evaluation.md)** | Manifest Auditing | Static security audit of browser extension permissions, content script injection, and client-side data leakage. |

### 5. Vulnerability Assessment & Foundational Principles
| Lab Document | Tools Used | Key Focus & Methodology |
| :--- | :--- | :--- |
| **[Vulnerability-Assessment (Day-3.md)](./Vulnerability-Assessment%20(Day-3).md)** | OpenVAS, Nessus | Automated vulnerability scanning, host discovery, CVE correlation, and remediation advisory generation. |
| **[Vulnerability Assessment & Risk Prioritization.md](./Vulnerability%20Assessment%20&%20Risk%20Prioritization.md)** | CVSS v3.1 Matrix | Prioritizing remediation backlogs using CVSS base, temporal, and environmental scores against business impact. |
| **[Fundamentals.md](./Fundamentals.md)** | Conceptual Reference | Core security axioms: CIA triad, Defense-in-Depth, Principle of Least Privilege, and attack surface reduction. |

---

## Technologies & Tools Used

* **Operating System:** Kali Linux, Ubuntu Server, Debian
* **Network & Scanning:** Nmap, Wireshark, Tshark, OpenVPN, cURL
* **Vulnerability Assessment:** Tenable Nessus, Greenbone OpenVAS, CVSS v3.1
* **Host & Firewall Defense:** UFW (Uncomplicated Firewall), iptables, OpenSSH hardening
* **Application Security:** SQLMap, DVWA (Damn Vulnerable Web App), Postman
* **Digital Forensics:** RFC 822 Email Parsers, Linux Syslog triage, OpenSSL

---

## Project Status

* **Status:** Complete Laboratory & Documentation Suite
* **Maintenance:** Archived reference portfolio representing foundational hands-on training.

---

## Author & Links

* **Author:** Siddh Samarth
* **GitHub:** [@SiddhSamarth](https://github.com/SiddhSamarth)
* **Portfolio:** [siddhsamarth.in](https://siddhsamarth.in)
* **LinkedIn:** [samarthsiddh](https://www.linkedin.com/in/siddhsamarth/)
