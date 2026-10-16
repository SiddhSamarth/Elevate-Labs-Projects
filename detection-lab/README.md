# Reproducible Detection: Repeated Windows Failed Logons

A small, reproducible blue-team exercise demonstrating a threshold-based detection for repeated Windows authentication failures.

## What is included

- `sample_windows_auth_events.jsonl`: synthetic Windows-style authentication events. All source IPs use documentation-only ranges defined for examples, not real attacker infrastructure.
- `detect_failed_logons.py`: reference implementation using the Python standard library.
- `sentinel_kql.kql`: Microsoft Sentinel query for events normalised into the SecurityEvent table.
- `expected_alerts.json`: expected output from the sample dataset using a threshold of five failed logons in a fixed ten-minute UTC bucket.
- `test_detection.py`: dependency-free tests for output, thresholding and successful-logon handling.

**This is a lab signal, not proof of malicious activity.** The query identifies a pattern that requires triage.

## Run locally

Python 3.9+ is recommended; no third-party packages are required.

From the repository root:

```bash
python3 detection-lab/detect_failed_logons.py detection-lab/sample_windows_auth_events.jsonl --threshold 5 --window-minutes 10
```

Compare the result with the checked-in expected output:

```bash
python3 detection-lab/detect_failed_logons.py detection-lab/sample_windows_auth_events.jsonl --threshold 5 --window-minutes 10 > /tmp/actual-alerts.json
diff -u detection-lab/expected_alerts.json /tmp/actual-alerts.json
```

No output from diff means the generated result matches the expected result.

Run the tests:

```bash
cd detection-lab
python3 -m unittest -v
```

## Detection logic

1. Keep Windows Security Event ID 4625 (failed logon) records.
2. Require a non-empty source IP and timestamp.
3. Group by source IP, computer and fixed ten-minute UTC bucket.
4. Alert when at least five failures occur in one bucket.
5. Return count, unique-account count, accounts and time range for analyst triage.

The Python detector deliberately uses fixed buckets, not a sliding window. Events that straddle a bucket boundary may therefore avoid alerting even when they are close together in time.

## Run in Microsoft Sentinel

Use `sentinel_kql.kql` in a workspace where Windows Security events are collected into the `SecurityEvent` table. Confirm the actual field names and data-connector configuration before running it. Do not assume the query is production-ready without testing against the target workspace's telemetry.

## Test cases and expected interpretation

| Source IP | Pattern | Expected result | Interpretation |
|---|---|---|---|
| 198.51.100.25 | Five failures across five account names on WIN-LAB-01 | Alert | Could be password guessing or password spraying; validate surrounding events and asset context. |
| 203.0.113.77 | Five failures against svc_backup on WIN-LAB-02 | Alert | Could be guessing or a misconfigured service using stale credentials; investigate before disposition. |
| 192.0.2.10 | Four failures on WIN-LAB-01 | No alert | Below threshold. Other rules may still be relevant. |
| 198.51.100.25 | One successful logon (Event ID 4624) | Not counted | Correlate success events separately to investigate whether a failure burst preceded a successful authentication. |

## False positives and limitations

Potential false positives include mistyped passwords, a service or scheduled task with stale credentials, shared NAT egress and authorised administrative testing. Triage account type, logon type, source asset, business hours, account-lockout events, preceding and subsequent success events, and endpoint telemetry before concluding malicious activity.

Potential false negatives include low-and-slow attacks below the threshold, distributed attempts from many IPs, missing source IPs, collection gaps, and events split across fixed bucket boundaries. Consider distinct-account detections and failure-to-success correlations only after reviewing your own baseline and testing the logic.

The sample does not measure production precision, recall or false-positive rate. Those metrics require labelled test data and telemetry that reflects the environment being monitored.

## Safety and provenance

All supplied events are **synthetic** and intended solely to test the detector. The IP addresses are reserved for documentation. No real users or systems are represented.
