# Vulnerability-Assessment

## 1. Executive Summary

The vulnerability assessment conducted on Windows 7 host in our home lab revealed insights into the patch levels of both the operating system & third-party software. This analysis provides a snapshot of potential security risks, aiding in the development of targeted remediation strategies to enhance the overall security posture of the Windows 7 environment.

## 2. Scan Results 

![image](https://github.com/laaaaaarry/Vulnerability-Management/assets/125237930/b7115be2-02f0-4d74-8569-9428adbc0674)

![image](https://github.com/laaaaaarry/Vulnerability-Management/assets/125237930/b5007278-5cee-49c1-acff-6d65a173bace)

![image](https://github.com/laaaaaarry/Vulnerability-Management/assets/125237930/e16cee21-233a-4017-8ff9-83be04a9276c)

![image](https://github.com/laaaaaarry/Vulnerability-Management/assets/125237930/42e0af42-5028-4de9-976b-2027c15a96aa)

![image](https://github.com/laaaaaarry/Vulnerability-Management/assets/125237930/2c1d78e5-dd7d-435d-a924-5d945f94c078)

![image](https://github.com/laaaaaarry/Vulnerability-Management/assets/125237930/d174dd49-a0fd-4477-87f5-c668b0d302c0)

![image](https://github.com/laaaaaarry/Vulnerability-Management/assets/125237930/7d1826f8-064a-416e-9786-8969ea45a928)

![image](https://github.com/laaaaaarry/Vulnerability-Management/assets/125237930/d78ff35e-99fc-48f0-ad97-216d912f566a)

![image](https://github.com/laaaaaarry/Vulnerability-Management/assets/125237930/2de21fa7-a16d-4ce2-8829-d0cb6895d53c)

## 3. Our Findings

Following a comprehensive patch audit of the Windows 7 host system, a total of 267 vulnerabilities were identified, categorized as 32 critical, 85 high, 7 medium, and 3 low severity issues. Additionally, 140 vulnerabilities were flagged with informative tags, highlighting a diverse range of areas for potential improvement and proactive security measures.

## 4. Risk Assessment

This report highlights security risks with the potential to exert a substantial impact on mission-critical applications integral to day-to-day business operations, emphasizing the need for proactive measures identified in the earlier vulnerability assessment.


| <img src="https://img.shields.io/badge/-Critical-FF0000?&style=for-the-badge&logoColor=white" /> | <img src="https://img.shields.io/badge/-High-FFA500?&style=for-the-badge&logoColor=white" /> | <img src="https://img.shields.io/badge/-Medium-FFFF00?&style=for-the-badge&logoColor=black" /> | <img src="https://img.shields.io/badge/-Low-00FF00?&style=for-the-badge&logoColor=black" /> |
|----------|----------|----------|----------|
| 32 | 85 | 7 | 3 |

### Critical Severity Vulnerability

32 were unique critical severity vulnerabilities. Critical vulnerabilities require immediate attention. They
are relatively easy for attackers to exploit and may provide them with full control of the affected systems.

A table of the top critical severity vulnerabilities is provided below: 

| Vulnerability | Description | Solution | CVSS | CVE |
|---------------|-------------|----------|------|-----|
| KB4571719: Windows 7 | A remote code execution vulnerability exists when Windows Media Audio Codec improperly handles objects. | Apply Security Only update KB4571719 or Cumulative Update KB4571729. | 10.0 | (CVE-2020-1339) |
| KB4525233: Windows 7 |  A remote code execution vulnerability exists when Windows Hyper-V on a host server fails to properly validate input from an authenticated user on a guest operating system. | Apply Security Only update KB4525233 or Cumulative Update KB4525235. | 9.9 | (CVE-2019-1389, CVE-2019-1397) |
| KB4556843: Windows 7 | A denial of service vulnerability exists when .NET Core or .NET Framework improperly handles web requests. | Apply Security Only update KB4556843 or Cumulative Update KB4556836. | 9.9 | (CVE-2020-1108) |
| KB5005089: Windows 7 | An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges. | Apply Security Only update KB5005089 or Cumulative Update KB5005088. | 9.9 | (CVE-2021-26425, CVE-2021-34483, CVE-2021-34484, CVE-2021-34537, CVE-2021-36927) |

### High Severity Vulnerability

 85 were unique high severity vulnerabilities. High severity vulnerabilities are often harder to exploit and
may not provide the same access to affected systems.

A table of the top high severity vulnerabilities is provided below: 

| Vulnerability | Description | Solution | CVSS | CVE |
|---------------|-------------|----------|------|-----|
| Security Updates for Internet Explorer | A memory corruption vulnerability exists. An attacker can exploit this to corrupt the memory and cause unexpected behaviors within the system/application. | Microsoft has released the following security updates to address this issue: KB5000800, KB5000841, KB5000844, KB5000847, KB5000848 | 8.8 | (CVE-2021-26411) |
| KB4503269: Windows 7 | An information disclosure vulnerability exists in the Windows Event Viewer (eventvwr.msc) when it improperly parses XML input containing a reference to an external entity. | Apply Security Only update KB4503269 or Cumulative Update KB4503292. | 8.8 | (CVE-2019-0948) |
| KB4537813: Windows 7 | A remote code execution vulnerability exists in the Windows Remote Desktop Client when a user connects to a malicious server. | Apply Security Only update KB4537813 or Cumulative Update KB4537820. | 8.8 | (CVE-2020-0681, CVE-2020-0734) |
| KB5004951: Windows 7 | A remote command execution vulnerability exists in Windows Print Spooler service improperly performs privileged file operations. An authenticated, remote attacker can exploit this to bypass and run arbitrary code with SYSTEM privileges. | Apply Cumulative Update 5004951 | 8.8 | (CVE-2018-16213) |

Given the substantial number of critical and high vulnerabilities, it is imperative to prioritize their resolution as an immediate and paramount concern. Addressing these vulnerabilities with urgency will fortify the security posture, allowing for a focused approach before delving into the remediation of other remaining vulnerabilities.

## Recommendations

It is imperative to prioritize the prompt resolution of critical vulnerabilities. Concurrently, establish a routine for regular monitoring and review of security bulletins issued by Microsoft. Implement robust network-level protections to mitigate potential exploits, and concurrently, conduct a thorough review of user access controls, enhancing them to minimize the risk of unauthorized access or exploitation. Additionally, prioritize the mitigation of high severity vulnerabilities and adopt general security improvements, such as endpoint protection and security awareness training, to fortify the overall security posture.

## Remediations

Taking the following actions we can greatly improve security posture of the Windows 7 host : 

| Vulnerability | Description | Solution |
|---------------|-------------|----------|
| Install KB5034831 | 91 | 1 |
| Install KB4516065 | 38 | 1 |
| Install KB4577010 | 27 | 1 |
| Install KB5006671 | 7 | 1 |
| Install KB4480055 | 2 | 1 |
| Install KB4457035 | 2 | 1 |
| Security Updates for Windows Malicious Software Removal Tool | 2 | 1 |
| Install KB4586768 | 1 | 1 |
| Security Updates for Microsoft Defender | 1 | 1 |

All vulnerabilities are documented in the report provided, necessitating immediate attention and management.
