# 🛡️ Phishing Email Analysis Report 

## 📌 Overview

This report presents a comprehensive manual investigation of a suspected phishing email named `sample1.eml`. The analysis was carried out using **Sublime Text Editor** on **Kali Linux 2025.2**, focusing on standard phishing indicators across email headers, content, and structure. The sample impersonates **Chase Bank** and attempts to deceive the recipient using urgency and domain obfuscation.

---

## 🧪 Analysis Summary

| Attribute                | Observed Value                                             | Assessment         |
|--------------------------|------------------------------------------------------------|--------------------|
| **From Address**         | `alerts@chase.com`                                          | ❌ Spoofed Identity |
| **Reply-To Address**     | `kellyellin426@proton.me`                                   | ❌ Mismatch         |
| **Return-Path**          | `kellyellin426@proton.me`                                   | ❌ Suspicious       |
| **Subject Line**         | `Your Bank Account has been blocked due to unusual activities` | ❌ Threat-Based     |
| **Tone of Email**        | Alarmist, urgent, action-triggering                        | ❌ Phishing Style   |
| **Embedded Links**       | `https://dsgo.to/CQEC...`                                   | ❌ Obfuscated URL   |
| **Displayed Link Text**  | `Reactivate Your Account`                                   | ❌ Deceptive Intent |
| **Attachments**          | _None detected_                                             | ✅ No Immediate Threat |
| **Header Anomalies**     | DKIM timeout, mismatched infrastructure                    | ❌ Spoof Evidence   |
| **Grammar and Spelling** | "tempory", improper capitalization                         | ❌ Red Flag         |

---

## 🔍 Key Findings

### 1. 🎭 Spoofed Identity

The email **pretends** to be from `alerts@chase.com`, but the true sender address and infrastructure reveal otherwise:
- **Reply-To:** `kellyellin426@proton.me`
- **Return-Path:** Same suspicious ProtonMail address
- **Relay Servers:** Hosted on `protonmail.ch` instead of Chase’s verified email servers

![image](https://github.com/user-attachments/assets/00c435ee-2ee6-4d81-9f38-4d3bab7126bf)

> 🧠 Spoofed sender domains can be used to deceive users into trusting malicious messages, especially if the display name appears familiar.

---

### 2. 🔗 Malicious Link Behavior

- **Displayed Text:** “Reactivate Your Account”
- **Actual Link:** `https://dsgo.to/CQEC...` (a URL shortener, not chase.com)
- **Tactic:** Uses a shortened, unbranded URL to hide its true destination

✅ For further safety checks, use tools like [VirusTotal](https://www.virustotal.com) or [URLScan.io](https://urlscan.io) to analyze suspicious URLs without clicking them.

---

### 3. ✉️ Header Discrepancies

Reviewing the raw headers via Sublime revealed:
- **SPF** passed, but **DKIM** returned a timeout — the email's authenticity remains unverified!           ![image](https://github.com/user-attachments/assets/e0f732fb-1488-4646-80fe-a3e6600b5db1)

- **SMTP Routing:** Relayed via ProtonMail servers, not Chase infrastructure.                                ![image](https://github.com/user-attachments/assets/67dbb23c-b8cc-4010-b252-2eab98d6a2bd)

- **Mismatch:** `From`, `Reply-To`, and `Return-Path` all show inconsistencies

> These header mismatches are clear signs of spoofing and identity concealment.

---

### 4. ⚠️ Psychological Manipulation

The email body attempts to create **urgency and fear**:
> _"Due to unusual activities on your account, we placed a tempory suspension until you verify your account."_

The language is **pressuring the user** to take immediate action, bypassing their judgment.

> ⚠️ This tactic is commonly used to rush victims into clicking phishing links without verifying their authenticity.

---

### 5. ✍️ Grammar & Spelling Red Flags

- “tempory” should be **temporary**
- Unnatural structure like “Click on ‘Reactivate Your Account’ below…” lacks professionalism

Phishing emails often contain such language issues because they are either auto-generated or written by non-native speakers — serving as an early warning sign.

![image](https://github.com/user-attachments/assets/9f712440-92ae-4d02-9e81-3a084f3abe9f)

---

## 🧰 Tools & Workflow

| Tool/Command           | Purpose                                      |
|------------------------|----------------------------------------------|
| **Sublime Text**       | Open and inspect raw `.eml` and HTML content |
| `grep`, `less`, `cat`  | Parse headers, extract suspicious fields     |
| **MXToolbox / Google Toolbox** | Header inspection and routing check        |
| **VirusTotal / URLScan.io** | URL scanning for threat reputation         |

---

## ✅ Final Verdict

This email exhibits **multiple classic phishing indicators**, including:

- Spoofed and mismatched sender addresses
- Obfuscated and suspicious links
- Use of fear-based language
- Poor grammar and formatting
- Suspicious routing paths in headers

> **Classification**: 🚨 Confirmed High-Risk Phishing Attempt  
> **Recommended Action**:  
> - Block sender and domain at the gateway  
> - Report the email to your internal SOC or IT security team  
> - Educate the recipient on phishing awareness  

---



