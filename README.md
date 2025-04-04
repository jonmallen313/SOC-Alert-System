SOC Alert System
A Python-based tool for real-time monitoring and alerting of brute-force login attempts on SSH and RDP services, designed for use in a Security Operations Center (SOC) environment. This project integrates with Elasticsearch to collect login data and sends alerts to Slack when suspicious activity is detected.

Features
Brute-Force Detection: Automatically detects failed login attempts on SSH and RDP, a common indicator of brute-force attacks.

Elasticsearch Integration: Queries Elasticsearch to retrieve data on failed login attempts.

Slack Alerts: Sends real-time notifications to a designated Slack channel when suspicious activity is detected.

Customizable Rules: Easily extend the script with more detection rules (such as monitoring other services or specific attack patterns).

MITRE ATT&CK Mapping (Planned): Future updates will map detected attacks to the MITRE ATT&CK framework for better understanding and reporting.

Prerequisites
Python 3.x

Elasticsearch instance running and accessible

Slack Webhook URL for sending alerts

Python libraries:

elasticsearch

slack_sdk

Installation
Clone the repository:

bash
Copy
Edit
git clone https://github.com/jonmallen313/SOC-Alert-System.git
cd SOC-Alert-System
Install the required dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Set up your configuration:

Create a .env file with the following environment variables:

ELASTICSEARCH_URL: URL of your Elasticsearch instance

SLACK_WEBHOOK_URL: Your Slack Webhook URL for sending alerts

Usage
Run the script:

bash
Copy
Edit
python alertbot.py
The script will:

Query your Elasticsearch instance for failed login attempts.

Check for patterns that match brute-force attack behavior.

Send alerts to your specified Slack channel when an attack is detected.

Configuration
You can customize the script by adding more detection rules or modifying existing ones. The script currently looks for SSH and RDP brute-force attempts but can be extended to cover additional services or attack patterns.

Future Plans
Integration with the MITRE ATT&CK framework for better attack classification.

Enhanced detection rules for various types of security incidents.

A frontend dashboard for visualizing alerts and activity.

Contributing
Feel free to fork the repository and submit pull requests. Contributions to improve detection capabilities, expand functionality, or improve documentation are always welcome!

License
This project is licensed under the MIT License - see the LICENSE file for details.
