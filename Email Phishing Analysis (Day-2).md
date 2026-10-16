# 🛡️ Phishing Email Analysis Report 

##  Overview

This report documents a manual review of the repository's sample1.eml training artifact. The message purports to be from Chase and contains multiple suspicious indicators. The raw-header artifact also contains an internal inconsistency between the visible From field and its recorded authentication results; this report therefore separates observed fields from interpretation.

---

## 🧪 Analysis Summary

| Attribute                | Observed Value                                             | Assessment         |
|--------------------------|------------------------------------------------------------|--------------------|
| **From Address**         | `alerts@chase.com`                                          | ⚠️ Visible identity is not authenticated by this field alone |
| **Reply-To Address**     | `kellyellin426@proton.me`                                   | ⚠️ Suspicious mismatch; corroborate |
| **Return-Path**          | `kellyellin426@proton.me`                                   | ❌ Suspicious       |
| **Subject Line**         | `Your Bank Account has been blocked due to unusual activities` | ❌ Threat-Based     |
| **Tone of Email**        | Alarmist, urgent, action-triggering                        | ❌ Phishing Style   |
| **Embedded Links**       | `https://dsgo.to/CQEC...`                                   | ❌ Obfuscated URL   |
| **Displayed Link Text**  | `Reactivate Your Account`                                   | ❌ Deceptive Intent |
| **Attachments**          | _None detected_                                             | ✅ No Immediate Threat |
| **Header Anomalies**     | DKIM timeout; Authentication-Results says header.from=protonmail.com while visible From is chase.com | ⚠️ Internally inconsistent artifact |
| **Grammar and Spelling** | "tempory", improper capitalization                         | ❌ Red Flag         |

---

## 🔍 Key Findings

### 1. Sender identity and reply routing

The sample contains these directly observed fields:

- Visible From: alerts@chase.com
- Reply-To: kellyellin426@proton.me
- Return-Path: kellyellin426@proton.me
- The relay-related fields reference Proton infrastructure.

The mismatch between the visible sender and the reply destination is a meaningful warning sign, particularly alongside the account-suspension theme. However, a From / Reply-To mismatch is not, by itself, proof of spoofing or malicious intent. State what the artifact shows and retain the original message for further validation.

### 2. 🔗 Malicious Link Behavior

- **Displayed Text:** “Reactivate Your Account”
- **Observed link:** a shortened dsgo.to URL (the destination was not verified in this report).
- **Interpretation:** the shortener obscures the final destination and warrants safe validation; use of a URL shortener alone is not proof of maliciousness.

✅ For further safety checks, use tools like [VirusTotal](https://www.virustotal.com) or [URLScan.io](https://urlscan.io) to analyze suspicious URLs without clicking them.

---

### 3. Authentication results and raw-header consistency

The sample's raw headers record:

- SPF pass for smtp.mailfrom=protonmail.com.
- DKIM timeout with header.d=protonmail.com.
- DMARC pass with header.from=protonmail.com.
- The visible message From field is alerts@chase.com.

A DKIM timeout is **inconclusive**, not a DKIM failure. An SPF pass establishes that the evaluated sending host was permitted for the recorded envelope-sender domain; it does not authenticate the visible From domain by itself.

The artifact is internally inconsistent: the recorded DMARC result names protonmail.com as the header-from domain, while the visible From field is alerts@chase.com. Preserve this discrepancy as a finding. Do not silently treat the authentication result as a valid DMARC pass for the visible From domain. The sample may have been edited, constructed, or had relevant headers altered; available evidence does not establish which explanation applies.

For a production investigation, validate the receiving system's trusted Authentication-Results header, the full Received chain, SPF/DKIM/DMARC alignment, and message trace where available.

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

## Final Assessment

### Observations

- The visible sender purports to be alerts@chase.com, while Reply-To and Return-Path reference a Proton address.
- The message uses an urgent account-suspension theme and a shortened URL whose final destination is not established in this report.
- The raw header's authentication fields contain an inconsistency: DMARC records header.from=protonmail.com, but the visible From field is alerts@chase.com.
- The DKIM status is a timeout, which is inconclusive.

### Disposition

**Classification: suspicious email; likely phishing based on the combined indicators, but the malicious destination and final delivery/authentication context have not been independently verified by this report.** Do not call the sample “confirmed phishing” solely from a DKIM timeout or sender mismatch.

Recommended handling for a real recipient:

1. Preserve the original EML and calculate a SHA-256 hash.
2. Report the message through the organisation's approved email-security process.
3. Do not click or open the shortened URL directly. Expand and inspect it only with an approved safe-analysis workflow; record redirect evidence and the timestamp.
4. Correlate mail gateway verdicts, message trace and recipient endpoint telemetry before concluding whether a user interacted with the message or whether compromise occurred.
5. Block a URL, sender or domain only after appropriate validation and according to the organisation's process.

### Limitations

This is a static lab sample review. It does not establish that the URL was malicious, that the message reached a real mailbox, that a user clicked it, or that credentials or systems were compromised. Any stronger conclusion must cite the additional evidence supporting it.

### References

- [NIST SP 800-177 Rev. 1 — Trustworthy Email](https://csrc.nist.gov/pubs/sp/800/177/r1/final)
- [RFC 7208 — Sender Policy Framework (SPF)](https://www.rfc-editor.org/rfc/rfc7208)
- [RFC 6376 — DomainKeys Identified Mail (DKIM)](https://www.rfc-editor.org/rfc/rfc6376)
- [RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc7489)
