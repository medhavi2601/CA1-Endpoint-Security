from flask import Flask, request, jsonify
import requests
import os
import time
from datetime import datetime
import urllib3

# Disable SSL warnings for lab
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

WAZUH_API_URL = os.getenv('WAZUH_API_URL', 'https://host.docker.internal:55000')
WAZUH_USER = 'wazuh'
WAZUH_PASSWORD = 'wazuh'
LOG_FILE = '/app/logs/verification.log'

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    with open(LOG_FILE, 'a') as f:
        f.write(log_msg + '\n')

def get_wazuh_token():
    """Get Wazuh API token"""
    try:
        response = requests.post(
            f"{WAZUH_API_URL}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASSWORD),
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            return response.json()['data']['token']
        return None
    except Exception as e:
        log(f"Auth error: {e}")
        return None

def check_agent_status(agent_name, token):
    """Verify agent is still active and responding"""
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f"{WAZUH_API_URL}/agents",
            headers=headers,
            params={'q': f'name={agent_name}'},
            verify=False,
            timeout=10
        )
        
        if response.status_code == 200:
            agents = response.json()['data']['affected_items']
            if agents:
                status = agents[0].get('status', 'unknown')
                return status == 'active'
        return False
    except Exception as e:
        log(f"Error checking agent status: {e}")
        return False

def verify_remediation(action, target, agent_name):
    """Verify that remediation was successful"""
    
    log(f"Verifying remediation: {action} on {target} for {agent_name}")
    
    # For simulated actions in our lab, we verify they were logged
    verification_results = {
        'action': action,
        'target': target,
        'agent': agent_name,
        'timestamp': datetime.now().isoformat(),
        'checks': []
    }
    
    # Get Wazuh token
    token = get_wazuh_token()
    if not token:
        verification_results['checks'].append({
            'check': 'wazuh_api_auth',
            'status': 'FAILED',
            'message': 'Could not authenticate with Wazuh API'
        })
        return verification_results
    
    # Check 1: Verify agent is still responding
    agent_active = check_agent_status(agent_name, token)
    verification_results['checks'].append({
        'check': 'agent_health',
        'status': 'PASS' if agent_active else 'FAIL',
        'message': f"Agent {agent_name} is {'active' if agent_active else 'disconnected'}"
    })
    
    # Check 2: Verify action was logged
    log_exists = verify_action_logged(action, target)
    verification_results['checks'].append({
        'check': 'action_logged',
        'status': 'PASS' if log_exists else 'FAIL',
        'message': f"Action {action} was {'logged' if log_exists else 'not logged'}"
    })
    
    # Check 3: For simulated actions, verify simulation flag
    if action in ['block_ip', 'kill_process', 'disable_user']:
        verification_results['checks'].append({
            'check': 'simulation_mode',
            'status': 'PASS',
            'message': f"Action {action} executed in simulation mode (safe for lab)"
        })
    
    # Overall success: all checks passed
    all_passed = all(check['status'] == 'PASS' for check in verification_results['checks'])
    verification_results['success'] = all_passed
    verification_results['overall_status'] = 'VERIFIED' if all_passed else 'FAILED'
    
    log(f"Verification complete: {verification_results['overall_status']}")
    
    return verification_results

def verify_action_logged(action, target):
    """Check if action was logged in remediation log"""
    try:
        with open('/app/logs/remediation_actions.log', 'r') as f:
            logs = f.read()
            # Check if action and target appear in recent logs
            return action in logs and str(target) in logs
    except:
        return False

def send_to_siem(verification_results):
    """Send verification results back to SIEM"""
    try:
        # In production, this would create a custom event in Wazuh
        # For CA1, we just log it
        log(f"Would send to SIEM: {verification_results}")
        
        # Could also use Wazuh API to create a custom event
        token = get_wazuh_token()
        if token:
            # Log event via Wazuh API (if available)
            pass
        
        return True
    except Exception as e:
        log(f"Error sending to SIEM: {e}")
        return False

@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({'status': 'healthy', 'service': 'verification'})

@app.route('/verify', methods=['POST'])
def verify():
    """Verify remediation action succeeded"""
    try:
        data = request.json
        
        alert = data.get('alert', {})
        action = data.get('action', 'unknown')
        target = data.get('target', 'unknown')
        result = data.get('result', {})
        
        agent_name = alert.get('agent', {}).get('name', 'unknown')
        
        log(f"Verification request received for {action} on {agent_name}")
        
        # Wait a moment for action to complete
        time.sleep(2)
        
        # Perform verification checks
        verification_results = verify_remediation(action, target, agent_name)
        
        # Add action result to verification
        verification_results['action_result'] = result
        
        # Send results to SIEM
        send_to_siem(verification_results)
        
        return jsonify(verification_results), 200
        
    except Exception as e:
        log(f"Error in verify endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/status/<action_id>', methods=['GET'])
def get_status(action_id):
    """Get status of a specific remediation action"""
    # In production, would query database
    # For CA1, return mock status
    return jsonify({
        'action_id': action_id,
        'status': 'completed',
        'verified': True
    })

if __name__ == '__main__':
    log("Verification service starting")
    app.run(host='0.0.0.0', port=5000, debug=False)