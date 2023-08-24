#!/var/ossec/framework/python/bin/python3

import sys
import json
import urllib3
import syslog
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

""" disable tls warnings """
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def read_config():
    try:
        # Read configuration from custom integration
        alert_file = open(sys.argv[1])
        api_key = sys.argv[2]
        hook_url = sys.argv[3]

        # Read the alert file
        alert_json = json.loads(alert_file.read())
        alert_file.close()

        return api_key, hook_url, alert_json
    except (FileNotFoundError, IndexError, json.JSONDecodeError) as e:
        msg = f"Failed to read config: {str(e)}"
        print(msg)
        syslog.syslog(syslog.LOG_ERR, msg)
        sys.exit(1)


# Create the request
def create_request(api_key, alert_json):
    try:
        description = alert_json["rule"].get("description", "")
        agent_name = alert_json["agent"].get("name", "")
        agent_ip = alert_json["agent"].get("ip", "")
        full_log = alert_json.get("full_log", "")
        timestamp = alert_json.get("timestamp", "")
        srcip = alert_json["data"].get("srcip", "")

        # Generate request
        headers = {"St2-Api-Key": api_key, "Content-Type": "application/json"}

        data = {
            "trigger": "core.st2.webhook",
            "timestamp": timestamp,
            "description": description,
            "agent_name": agent_name,
            "agent_ip": agent_ip,
            "full_log": full_log,
            "srcip": srcip,
        }
        return headers, data
    except KeyError as e:
        msg = f"Failed to create request: {str(e)}"
        print(msg)
        syslog.syslog(syslog.LOG_ERR, msg)
        sys.exit(1)


# Send the request
def send_request(hook_url, headers, data):
    try:
        proxies = {
            "http": "http://172.20.72.11:8888",
            "https": "https://172.20.72.11:8888",
        }
        response = requests.post(
            hook_url,
            headers=headers,
            json=data,
            verify=False,
            timeout=5,
            proxies=proxies,
        )
        if response.status_code // 100 == 2:
            msg = "Request sent successfully"
            print(msg)
            syslog.syslog(syslog.LOG_INFO, msg)
        else:
            msg = f"Failed to send request, status code: {response.status_code}"
            print(msg)
            syslog.syslog(syslog.LOG_ERR, msg)
        return response
    except RequestException as e:
        msg = f"Failed to send request: {str(e)}"
        print(msg)
        syslog.syslog(syslog.LOG_ERR, msg)
        sys.exit(1)


# Main function
if __name__ == "__main__":
    api_key, hook_url, alert_json = read_config()
    headers, data = create_request(api_key, alert_json)
    response = send_request(hook_url, headers, data)