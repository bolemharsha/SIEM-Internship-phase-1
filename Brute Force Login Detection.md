
# 🚨 Brute Force Followed by Privileged Login

## 🎯 Detection Objective
Detect a brute-force login attack followed by a successful privileged login using Windows Event IDs:  
- `4625` → Failed login  
- `4624` → Successful login  

Set up alerts using Kibana (Elasticsearch stack) and ElastAlert.

---

## 🛠️ Tools Used
- **SIEM Stack**: Elasticsearch, Kibana  
- **Log Forwarders**: Winlogbeat, Sysmon  
- **Target OS**: Windows 10 (Victim VM)  
- **Attacker Machine**: Kali Linux  
- **Attacking Tool**: Hydra  

---

## 🧪 Lab Setup
1. Installed **Winlogbeat** on a Windows VM (victim) to forward logs to Elasticsearch.
2. Installed and configured **Elasticsearch** and **Kibana** on a separate monitoring system.
3. Set up **ElastAlert** with a detection rule:
   - Detects **10 failed login attempts (Event ID 4625)** from the same IP within 5 minutes.
   - Sends an **email alert** using Gmail SMTP.
4. Performed a **brute-force attack simulation** using Hydra.
5. Verified alert in email.
6. Faced and resolved configuration errors in `config.yaml` and `rule.yaml` related to missing fields.

---

## 🧠 Detection Logic
- Track **failed logins** using Event ID `4625`.
- If **10 or more** failed login attempts occur from the **same IP** within **5 minutes**, trigger an alert.
- Optionally, correlate this with a **successful login** (Event ID `4624`) from the same IP.

---

## 🔍 Elasticsearch Query DSL
```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.code": "4625" }},
        {
          "range": {
            "@timestamp": {
              "gte": "now-5m",
              "lte": "now"
            }
          }
        }
      ]
    }
  },
  "aggs": {
    "by_ip": {
      "terms": {
        "field": "host.ip",
        "size": 10
      },
      "aggs": {
        "event_count": {
          "value_count": {
            "field": "event.code"
          }
        },
        "filter_by_minimum": {
          "bucket_selector": {
            "buckets_path": {
              "count": "event_count"
            },
            "script": "params.count >= 10"
          }
        }
      }
    }
  },
  "size": 0
}
```

---

## 🔎 Kibana Detection Query
```kql
event.code: "4625" AND host.ip: "192.168.x.x"
```

Replace `192.168.x.x` with the IP used in your test (e.g., Kali attacker machine).

---

## 📊 Data Source Mapping

| Source            | Event ID | Description                                      |
|-------------------|----------|--------------------------------------------------|
| Winlogbeat        | 4625     | Failed login attempt                             |
| Winlogbeat        | 4624     | Successful login                                 |
| Sysmon (optional) | 1        | Process creation (track attacker tooling)        |
| Winlogbeat        | 4672     | Privilege escalation (admin logon event)         |

---

## 📩 Sample Alert (Email Screenshot)
![Sample Alert Screenshot](https://github.com/user-attachments/assets/5fdc4124-44c0-44a7-b367-f0a08c74532c)

---

## 🧾 Sample Event Log
![Sample 4625 Event](https://github.com/user-attachments/assets/ae380541-6ef3-40a4-b644-2760dddd9f4d)

---

## 🛡️ Recommendations

### 🔍 Analyst Action on Alert
- Review the source IP address.
- Confirm login time and user identity.
- Check for a sequence of failed logins followed by a success.
- Investigate for signs of privilege escalation or lateral movement.

### ⚠️ Possible False Positives
- Admins mistyping passwords before successful login.
- Legitimate scheduled tasks or services failing authentication.
- Misconfigured applications attempting to authenticate repeatedly.

### ✅ Mitigation Advice
- Enforce strong password policies.
- Implement Multi-Factor Authentication (MFA).
- Use account lockout policies.
- Whitelist known IPs or internal scanners if needed.

---

## ✅ Detection Status
**Successfully Triggered**  
ElastAlert sent email alert upon detecting the brute-force sequence.
