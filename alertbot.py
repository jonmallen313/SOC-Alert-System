import requests
from elasticsearch import Elasticsearch
import json
import os
import urllib3
from dotenv import load_dotenv
import time
from datetime import datetime, timedelta
load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Elasticsearch setup
es = Elasticsearch(
    "https://140.82.43.164:9200",
    basic_auth=(os.getenv("ES_USER"), os.getenv("ES_PASS")),
    verify_certs=False
)

# File to store the last seen alert timestamp
LAST_SEEN_FILE = "last_seen.json"

def load_last_seen():
    """Load the last seen timestamps from the file."""
    if os.path.exists(LAST_SEEN_FILE):
        with open(LAST_SEEN_FILE, "r") as f:
            return json.load(f)
    return {}

def save_last_seen(data):
    """Save the last seen timestamps to the file."""
    with open(LAST_SEEN_FILE, "w") as f:
        json.dump(data, f)

def update_last_seen(alert_type, new_timestamp, last_seen_data):
    """Update the last seen timestamp for the given alert type."""
    last_seen_data[alert_type] = new_timestamp
    save_last_seen(last_seen_data)

# Load initial last seen data
last_seen_data = load_last_seen()

print("Elasticsearch connection established.")

# Query for SSH brute force attempts
ssh_query = {
    "query": {
        "bool": {
            "must": [
                { "term": { "system.auth.ssh.event": "Failed" }},
                { "term": { "agent.name": "Linux-guru" }},
                { "term": { "user.name": "root" }}
            ],
            "filter": [
                { "range": { "@timestamp": { "gte": "now-1m" }}}
            ]
        }
    }
}

# Query for RDP brute force attempts
rdp_query = {
    "query": {
        "bool": {
            "must": [
                { "term": { "event.code": "4625" }},  # RDP failed login event code
                { "term": { "agent.name": "WIN-guru" }}  # Agent name for RDP
            ],
            "filter": [
                { "range": { "@timestamp": { "gte": "now-1m" }}}
            ]
        }
    }
}

# Query for suspicious login behavior (failed followed by successful login)
suspicious_login_query = {
    "query": {
        "bool": {
            "must": [
                { "term": { "event.action": "failed_login" }},
                { "term": { "event.action": "successful_login" }}
            ],
            "filter": [
                { "range": { "@timestamp": { "gte": "now-10m" }}},
                { "terms": { "user.name": ["username_1", "username_2"] }},
                { "terms": { "source.geo.city_name": ["unusual_city_1", "unusual_city_2"] }}
            ]
        }
    }
}

# Query for privilege escalation (sudo/su commands)
privilege_escalation_query = {
    "query": {
        "bool": {
            "must": [
                { "term": { "event.action": "sudo" }},
                { "term": { "user.name": "non_admin_user" }}
            ]
        }
    }
}

# Query for suspicious PowerShell execution (Invoke-Expression)
powershell_suspicious_query = {
    "query": {
        "bool": {
            "must": [
                { "term": { "process.name": "powershell.exe" }},
                { "match": { "process.args": "Invoke-Expression" }}
            ]
        }
    }
}

# Query for ransomware file extensions
ransomware_file_query = {
    "query": {
        "bool": {
            "must": [
                { "term": { "file.extension": "encrypted" }},
                { "term": { "file.extension": "locked" }}
            ]
        }
    }
}

# Query for large outbound data transfer (potential data exfiltration)
data_exfiltration_query = {
    "query": {
        "bool": {
            "must": [
                { "term": { "network.direction": "outbound" }},
                { "range": { "network.bytes": { "gte": 10000000 }}}
            ]
        }
    }
}

# Query for port scanning activity (multiple connections to different ports)
port_scan_query = {
    "query": {
        "bool": {
            "must": [
                { "term": { "event.action": "connection_attempt" }},
                { "term": { "network.type": "ipv4" }}
            ],
            "filter": [
                { "range": { "@timestamp": { "gte": "now-10m" }}}
            ]
        }
    }
}

# Function to send a Slack message
def send_slack_alert(message):
    slack_webhook_url = "https://hooks.slack.com/services/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"  # Full URL
    slack_message = {
        "text": message
    }
    headers = {'Content-Type': 'application/json'}
    print(f"Sending Slack message: {message}")
    response = requests.post(slack_webhook_url, data=json.dumps(slack_message), headers=headers)
    if response.status_code != 200:
        print(f"Error sending message to Slack: {response.status_code}")
    else:
        print(f"Message sent to Slack: {message}")

def check_brute_force(query, alert_type, last_check_time):
    """Check for brute force attempts and send an alert if any new attempts are found."""
    try:
        print(f"Running query for {alert_type} brute force...")  # Debugging line
        response = es.search(index="apm-*-transaction*,auditbeat-*,endgame-*,filebeat-*,logs-*,packetbeat-*,traces-apm*,winlogbeat-*,-*elastic-cloud-logs-*", body=query)
        print(f"Response: {response}")  # Debugging line
        hits = response['hits']['total']['value']
        print(f"Hits for {alert_type} brute force: {hits}")  # Debugging line

        if hits > 0:
            # Extract relevant details from the first hit
            first_hit = response['hits']['hits'][0]['_source']
            latest_event_time = first_hit.get('@timestamp')
            source_ip = first_hit.get('source', {}).get('ip', 'N/A')
            user_name = first_hit.get('user', {}).get('name', 'N/A')

            # Check if we've already alerted for this timestamp
            last_seen = last_seen_data.get(alert_type)

            if last_seen is None or latest_event_time > last_seen:
                message = (
                    f"{alert_type} Brute Force attempt detected!\n"
                    f"• Attempts: {hits}\n"
                    f"• Source IP: {source_ip}\n"
                    f"• User: {user_name}"
                )
                send_slack_alert(message)
                update_last_seen(alert_type, latest_event_time, last_seen_data)
            else:
                print(f"No new {alert_type} alerts since last_seen: {last_seen}")
        else:
            print(f"No {alert_type} brute force attempts detected.")  # Debugging line
    except Exception as e:
        print(f"Error in query execution: {e}")  # Debugging line

# Function to get the current timestamp as a string in Elasticsearch query format
def get_current_timestamp():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')

# ⏱️ Monitoring loop
last_check_time = (datetime.utcnow() - timedelta(minutes=1)).isoformat()

while True:
    try:
        # Check both SSH and RDP brute force attempts
        check_brute_force(ssh_query, "SSH", last_check_time)
        check_brute_force(rdp_query, "RDP", last_check_time)
        check_brute_force(suspicious_login_query, "Suspicious Login", last_check_time)
        check_brute_force(privilege_escalation_query, "Privilege Escalation", last_check_time)
        check_brute_force(powershell_suspicious_query, "Suspicious PowerShell Execution", last_check_time)
        check_brute_force(ransomware_file_query, "Ransomware File", last_check_time)
        check_brute_force(data_exfiltration_query, "Data Exfiltration", last_check_time)
        check_brute_force(port_scan_query, "Port Scan", last_check_time)
        


        # Update last checked time to now
        last_check_time = datetime.utcnow().isoformat()

        # Wait 60 seconds before next check
        time.sleep(60)
    except Exception as e:
        print(f"❌ Error in main loop: {e}")
        time.sleep(60)
