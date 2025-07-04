# 🛡️ Identify and Remove Suspicious Browser Extensions

---

## 🎯 Objective

To analyze browser extensions for privacy and security risks, remove those that are unnecessary or potentially malicious, and gain hands-on experience in browser hardening practices.

---

## 🛠️ Tools Used

| Tool                      | Purpose                                                  |
|---------------------------|----------------------------------------------------------|
| Google Chrome / Firefox   | Browsers used for extension inspection                   |
| Built-in Extension Manager| To manage installed add-ons                              |
| Chrome Web Store / AMO    | Research developer credibility and extension reviews     |
| Web search (Google, Reddit)| Research extension reputation from user forums & articles|

---

## 📖 Why This Task Matters

Extensions can greatly enhance browser functionality, but they can also:

- Access sensitive data (e.g., passwords, emails, browser history)
- Inject malicious ads or redirects
- Exfiltrate data to third-party servers
- Slow down browser performance
- Act as spyware in disguise

A **2020 study** by researchers from **Stanford** and **UC Berkeley** found that over **10% of Chrome extensions** with 1M+ users had some form of **excessive tracking or data collection**. Hence, vigilance is key.

---

## 📋 Step-by-Step Procedure

### 🔍 Step 1: Open Extension Manager
- **Chrome**: `chrome://extensions/`
- **Firefox**: `about:addons`

---

### 🔎 Step 2: Review Each Extension Carefully
- Review the following attributes:
  - Extension **name**
  - **Developer / Publisher**
  - **Number of downloads**
  - **Ratings and reviews**
  - **Permissions requested**
- Use tools like [crxcavator.io](https://crxcavator.io/) and [Extension Monitor](https://extensionmonitor.com/) for further analysis (if available).

---

### 🚩 Step 3: Identify Suspicious Extensions
Flag extensions if:
- You don’t remember installing them
- They request **“Read and change all your data on websites”**
- They have low ratings, poor reviews, or haven’t been updated in years
- They're known to inject ads or track you aggressively

---

### ❌ Step 4: Remove or Disable
- **Remove** anything flagged as suspicious or not in use.
- **Disable** if you’re unsure but want to test without full removal.

---

### 🔄 Step 5: Restart Browser
- After making changes, restart the browser.
- Check if performance improves (faster page loads, fewer pop-ups, smoother UI).

---

## 🧠 Step 6: How Malicious Extensions Can Harm Users

| Threat                  | Description                                                             |
|-------------------------|-------------------------------------------------------------------------|
| Credential Theft        | Harvest saved login data from web forms                                |
| Ad Injection            | Replace real ads with injected ones for profit                          |
| Cryptojacking           | Use your CPU/GPU to mine cryptocurrency without consent                 |
| Surveillance            | Track all browsing activity for resale to advertisers or malicious actors|
| Redirection             | Modify search results or links to redirect you to phishing pages        |

---

## 📝 Extension Review Log

| Extension Name              | Status     | Research Summary / Notes                                                |
|-----------------------------|------------|-------------------------------------------------------------------------|
| **AdBlocker Ultimate**      | ✅ Kept    | Popular and effective ad blocker. Minimal permissions. Trusted.         |
| **Ghostery Tracker Blocker**| ✅ Kept    | Excellent for privacy. Actively maintained. Open-source.                |
| **Grammarly: AI Writing**   | ✅ Kept    | Useful, widely used. Collects text input but operates transparently.    |
| **Malwarebytes Browser Guard** | ✅ Kept | Shields from scams and malicious domains. Reputable vendor.             |
| **McAfee WebAdvisor**       | ⚠️ Removed | Redundant with Malwarebytes. Mixed reviews. May slow browsing.          |
| **Merlin – Ask AI (ChatGPT)**| ⚠️ Removed | Uses OpenAI backend. Not officially verified. Privacy concerns raised.  |
| **MetaMask**                | ✅ Kept    | Must-have for Web3 users. Widely trusted and security-focused.          |
| **Netcraft Extension**      | ✅ Kept    | Great for detecting phishing. Maintained by a security firm.            |
| **Pie Adblock**             | ❌ Removed | Redundant due to AdBlocker Ultimate. Unknown vendor.                    |

---

