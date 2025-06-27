# Elevate Labs Projects

A comprehensive suite of instructor-guided cybersecurity labs completed during the Elevate Labs program. Each lab simulates a real-world scenario, reinforcing core security principles through hands-on exercises, detailed documentation, and critical analysis.

---

## 📂 Repository Contents

| File                                    | Description                                                                                                     |
|-----------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| **Network Scan (Day-1).md**             | Guided Nmap reconnaissance: host discovery, port/service enumeration, version detection, and OS fingerprinting. |
| **Email Phishing Analysis (Day-2).md**   | In-depth phishing email forensics: header parsing, URL/attachment analysis, and IOC identification.              |
| **Vulnerability-Assessment (Day-3).md**  | Combined automated (OpenVAS/Nessus) and manual vulnerability scanning of a Windows 7 target with risk rating.  |
| **Basic Firewall Configuration (Day-4).md** | UFW lab on Kali Linux: rule creation, traffic filtering, insecure port blocking, verification, and cleanup.     |
| **sample1.eml**                         | Sample phishing email used for Day-2 analysis.                                                                  |

---

## 🎯 Objectives & Key Takeaways

Each module hones a distinct facet of cybersecurity practice:

1. **Network Reconnaissance**  
   - Map network topology and identify live hosts.  
   - Enumerate open ports & services; perform version/OS fingerprinting.  
   - Analyze scan results to build an actionable network profile.

2. **Phishing Detection & Analysis**  
   - Extract and dissect email headers for origin and routing anomalies.  
   - Examine embedded URLs and attachments for malicious payloads.  
   - Correlate Indicators of Compromise (IOCs) and craft mitigation advice.

3. **Vulnerability Assessment**  
   - Execute automated scans (OpenVAS, Nessus) to uncover vulnerabilities.  
   - Perform manual validation of critical findings.  
   - Classify risks (CVSS scores), prioritize remediations, and document action plans.

4. **Host Hardening & Firewall Management**  
   - Define and enforce least-privilege network policies with UFW.  
   - Create, test, and validate firewall rules for SSH, Telnet, and other services.  
   - Implement cleanup procedures to restore a secure baseline.

---

## 🛠️ Tools & Technologies

- **Platform:** Kali Linux  
- **Reconnaissance:**  
  - Nmap (host discovery, service enumeration, OS detection)  
- **Email Forensics:**  
  - `mailx`, Wireshark, text-based header parsers  
- **Vulnerability Scanning:**  
  - OpenVAS, Nessus (or equivalent), manual inspection tools  
- **Firewall Configuration:**  
  - UFW (Uncomplicated Firewall) via CLI  
- **Documentation:**  
  - Markdown, embedded screenshots, code snippets for reproducibility  

---

## 📖 Getting Started

1. **Clone the repository**  
   ```bash
   git clone https://github.com/SiddhSamarth/Elevate-Labs-Projects.git
   cd Elevate-Labs-Projects
