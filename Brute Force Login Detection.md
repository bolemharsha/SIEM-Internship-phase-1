# Brute Force Followed by Privileged Login

## Detection Objective: 
 To detect a brute-force login attack followed by a successful privileged login using Windows Event Logs: 4625 (failure), 4624 (success) and managed, configure an alert in Kibana via Elastic Stack.    
## Tools:
•	SIEM Stack: Elasticsearch, Kibana.

•	Log Forwarders: Sysmon, Winlogbeat 

•	Target OS: Windows 10 (victim VM)

•	Attacker Machine: Kali Linux

•	Attacking Tool: Hydra Tool

## Lab Setup:
	
Installed Winlogbeat in a Windows VM to forward security logs to Elasticsearch. Then, I set up Elasticsearch and Kibana to store and view logs. Configured ElastAlert with a rule to detect 10 failed login attempts (event  ID 4625) from the same IP within 5 minutes. Triggered a brute-force simulation and successfully received an alert via email using Gmail SMTP. While setting up the ElastAlert configuration I had faced my many throwing errors because of missing required fields in the config.yaml and rule.yaml files. 
## Detection Logic:
	
Detect if 10 or more failed login attempts (Event ID 4625) are observed from the same IP address within 5 minutes, and send an email alert.

## Elasticsearch Query DSL:
    {
      "query": {
        "bool": {
          "must": [
            { "term": { "event.code": "4625" }},
            { "range": {
                "@timestamp": {
                  "gte": "now-5m",
                  "lte": "now"
                }
            }}
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

## Kibana Detection Query:
    Event.code: “4625” AND host.ip: “*” 
You can you add your suspicious IP also "192.168.x.x"
## Data Source Mapping:
  | Source            | Event ID | Description                                      |
  |-------------------|----------|--------------------------------------------------|
  | Winlogbeat        | 4625     | Failed login attempt                             |
  | Winlogbeat        | 4624     | Successful login                                 |
  | Sysmon (optional) | 1        | Process creation (can be used to track attacks)  |
  | Winlogbeat        | 4672     | Special privileges assigned to new logon         |
## Sample Alert
![Screenshot 2025-05-15 220749](https://github.com/user-attachments/assets/5fdc4124-44c0-44a7-b367-f0a08c74532c)


## Sample Event
![event code 4625](https://github.com/user-attachments/assets/ae380541-6ef3-40a4-b644-2760dddd9f4d)


## Recommendation:
### What should an analyst do when this alert triggers?
  When this alert triggers, the analyst should verify the source IP and user involved, confirm the sequence of failed and successful logins, check for any privilege escalation, and take immediate action if malicious activity is suspected.
### Possible false positives?
  •	Check if the login attempts align with the user’s normal login times and IP addresses.
  
  •	Exclude known internal or management IPs from alerts if they’re frequently used for administrative tasks.
  
  •	Ensure that Multi-Factor Authentication is enforced, making brute-force attempts less effective even if successful.
## Detection Status:
### Successfully Triggered  ✅



























