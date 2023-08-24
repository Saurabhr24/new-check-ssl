import ssl
import socket
import datetime
import requests
import os
import sys

def check_ssl_expiry(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            expire_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (expire_date - datetime.datetime.utcnow()).days
            return days_until_expiry

def send_slack_alert(domain, days_until_expiry):
    webhook_url = os.getenv('SLACK_WEBHOOK_URL')
    message = f"SSL Expiry Alert\nDomain: {domain}\nWarning: The SSL certificate for {domain} will expire in {days_until_expiry} days."
    payload = {
        "text": message
    }
    response = requests.post(webhook_url, json=payload)
    if response.status_code != 200:
        print(f"Failed to send Slack alert for {domain}")

# Get domains from command line argument
domains_str = sys.argv[1]
domains = domains_str.split(',')

for domain in domains:
    remaining_days = check_ssl_expiry(domain)
    if remaining_days is not None and remaining_days <= 30:
        send_slack_alert(domain, remaining_days)
