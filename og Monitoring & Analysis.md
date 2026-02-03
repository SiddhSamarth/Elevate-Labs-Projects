

# SIEM Hands-On Learning Plan: From Log Types to Alerts & Reporting

This guide takes you from understanding log types to building dashboards, analyzing authentication logs, detecting anomalies, correlating events, writing alerts, and documenting findings — with visuals that make abstract concepts concrete.

---

## What is SIEM?

SIEM (Security Information and Event Management) collects logs from across an organization, normalizes, correlates, and analyzes them in real time to detect threats, support investigations, and help with compliance reporting. SIEM centralizes security data from endpoints, firewalls, servers, and applications into one searchable system and generates alerts and dashboards that show patterns in visual form. ([Splunk][1])

---

## 1) Prepare Your Log Environment

### Visual — SIEM Architecture & Data Pipeline

![Image](https://www.logsign.com/uploads/siem_architecture_11_638_7ce86e090c.jpg)

![Image](https://substackcdn.com/image/fetch/w_1456%2Cc_limit%2Cf_auto%2Cq_auto%3Agood%2Cfl_progressive%3Asteep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F5244cbee-8937-468d-b1b6-758cbcafbc75_1920x1080.png)

![Image](https://www.logsign.com/uploads/13_1_6cb8094ab7.png)

![Image](https://www.logsign.com/uploads/1_6_1024x503_b889de5bcb.png)

**What this visual shows:**

* SIEM collects logs from many systems: operating systems, authentication services, firewalls, applications, IDS/IPS, network devices.
* Logs are merged into a unified platform that normalizes different formats.
* A correlation engine analyzes them for patterns and anomalies.
* Dashboards and alerts provide visual insights into security activity. ([SOC Masters][2])

---

## 2) Analyze Authentication Logs

Authentication logs show *who tried to log in, when, from where, and whether it succeeded or failed*. These logs are critical for identifying access attempts, misconfigurations, or malicious login attempts.

### Visual — Authentication Traffic Dashboard

![Image](https://media.licdn.com/dms/image/v2/D4D12AQGODiJh-XWu1w/article-cover_image-shrink_720_1280/B4DZU9Qx4THAAI-/0/1740489564518?e=2147483647\&t=NjKq7ydIW8Q2VqpOFofjFKBz8b-gZ4Jipqe0_Gcmrhw\&v=beta)

![Image](https://www.slideteam.net/media/catalog/product/cache/1280x720/c/y/cyber_intelligence_risk_assessment_dashboard_with_heat_map_slide01.jpg)

![Image](https://community.splunk.com/t5/image/serverpage/image-id/9799i50E2923057DA4FC9/image-dimensions/764x134?v=v2)

![Image](https://community.splunk.com/t5/image/serverpage/image-id/9619iC78E3EE73E97716C/image-size/large?px=999\&v=v2)

**What to look for visually:**

* Trends in failed vs successful logins.
* Login attempts over time.
* Geographical sources of logins.
* Spike patterns that might indicate brute-force attacks. ([Logit.io][3])

**Why it matters:** By visualizing login events, you can quickly identify unusual patterns that might be invisible in raw log text (e.g., sudden surge in failures, or logins from unexpected regions). ([Splunk][4])

---

## 3) Identify Failed Logins

Failed authentication attempts often signal:

* Brute-force attacks
* Misconfigured credentials
* Automated login tools
* Credential stuffing

**Splunk query example:**

```splunk
index=auth status=failure
| stats count by src_ip
| where count > 10
```

→ Alert when >10 failures occur from the same IP within your analysis window. ([Splunk][5])

---

## 4) Detect Anomalies (Behavioral Deviations)

Anomalies are departures from baseline behavior — for example:

* A user logging in at 3 AM when they normally access systems at business hours.
* Geographic anomalies where logins originate from countries with no user presence.
* Spikes in access failures from specific accounts.

### Visual — Example Anomaly Alerts & Thresholds

![Image](https://www.manageengine.com/log-management/cyber-security/images/visual-anomaly-reports-and-dashboards.png)

![Image](https://www.splunk.com/en_us/blog/platform/media_170b09052f86ffa5926554070f5c270689e226697.avif?format=pjpg\&optimize=medium\&width=1200)

![Image](https://www.researchgate.net/publication/359562811/figure/fig3/AS%3A11431281360816613%401744099755030/Timeline-for-evolution-of-anomaly-detection-techniques.png)

![Image](https://www.researchgate.net/publication/353416177/figure/fig3/AS%3A1048981119459330%401627107996525/Timeline-for-the-real-time-detection-of-suspicious-event-for-the-abnormal-activity.png)

This visual reinforces the idea of *baseline vs unexpected behaviour*, an essential part of identifying suspicious activity.

---

## 5) Correlate Events

Event correlation links individual logs into meaningful sequences — for example:

* Many failed login attempts → one successful login → unusual privilege use
* Failed SSH logins from multiple hosts focused on `root` account
* Firewall block events followed by surges in traffic

**Splunk correlation rule example:**

```splunk
index=auth
| transaction user maxspan=5m
| search events > 3
```

This looks for multiple events around the same user within a 5-minute window.

Correlation is what turns *many unrelated log lines* into an *examined security incident*. ([Medium][6])

---

## 6) Learn SIEM Basics — Tools & Workflow

You can practice SIEM fundamentals using:

* **Splunk (Free or Enterprise)** — centralized ingestion, search, dashboards, alerts, analytics
* **ELK/OpenSearch Stack (with Kibana dashboards)** — log ingestion (Beats/Logstash), indexing (Elasticsearch/OpenSearch), visualization (Kibana/Dashboards) ([Logz.io][7])
* **Security Onion / Wazuh** — built-in SIEM + rule sets for detections and alerts ([LinkedIn][8])

SIEM Basics:
✔ log ingestion & normalization
✔ search & filtering
✔ dashboards & visual analytics
✔ correlation rules
✔ real-time alerts
✔ reporting and documentation — all part of SOC workflows. ([Splunk][1])

---

## 7) Write Alerts

Alerts are rules that trigger when suspicious conditions occur.

**Types of alerts:**

* **Threshold-based:** e.g., 10+ failed logins from an IP
* **Pattern-based:** e.g., failed login followed by successful login
* **Behavioral:** departure from learned baseline

**Splunk example:**

```splunk
index=auth status=success
| where src_ip NOT IN ([trusted list])
```

Alerts help SOC analysts focus on *priority threats* instead of noise. ([Splunk][1])

---

## 8) Document Findings

Documentation brings together your observations from queries, dashboards, alerts, and context.

Your analysis should include:

1. Timeframe of investigation
2. Data sources analysed
3. Queries or alerts used
4. Findings (evidence, correlations, anomalies)
5. Severity assessments
6. Actionable recommendations

Documentation serves as an *incident report* that can be shared with SOC leads, auditors, and stakeholders. ([Splunk][4])

---

## Example Learning Exercise (Practice Plan)

| Step | Task                                                     |
| ---- | -------------------------------------------------------- |
| 1    | Set up Splunk or ELK locally                             |
| 2    | Ingest auth, SSH, web, firewall logs                     |
| 3    | Run SPL/KQL queries to identify failed logins            |
| 4    | Create dashboards for trends and anomalies               |
| 5    | Define correlation rules for multi-stage attack patterns |
| 6    | Create alert rules for key use cases                     |
| 7    | Document findings in a report                            |

---

## Tools & Queries Cheatsheet

| Tool        | Query Example                         | Goal                        |                              |
| ----------- | ------------------------------------- | --------------------------- | ---------------------------- |
| **Splunk**  | `stats count by user, status`         | Count login results         |                              |
| **Splunk**  | `search status=failure                | stats count by src_ip`      | Detect failed login patterns |
| **ELK/KQL** | `@event.action: "failed"`             | Identify failed auth events |                              |
| **ELK/KQL** | `geo.src:* anomaly_score > threshold` | Detect unusual locations    |                              |



