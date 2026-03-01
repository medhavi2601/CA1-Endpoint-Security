from flask import Flask, request, jsonify
import os
import json
from datetime import datetime
from actions import RemediationActions
import requests

app = Flask(__name__)

WINDOWS_HOST = os.getenv('WINDOWS_HOST', '192.168.100.10')
LINUX_HOST = os.getenv('LINUX_HOST', '192.168.100.20')
ALLOWED_ACTIONS = os.getenv('ALLOWED_ACTIONS', 'block_ip,kill_process').split(',')
LOG_FILE = '/app/logs/remediation_engine.log'

# Initialize actions handler
actions = RemediationActions(WINDOWS_HOST, LINUX_HOST)

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    with open(LOG_FILE, 'a') as f:
        f.write(log_msg + '\n')

@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'service': 'remediation-engine',
        'allowed_actions': ALLOWED_ACTIONS
    })

@app.route('/remediate', methods=['POST'])
def remediate():
    """Execute remediation action"""
    try:
        data = request.json
        alert = data.get('alert', {})
        ai_analysis = data.get('ai_analysis', {})
        
        # Extract information
        rule_id = alert.get('rule', {}).get('id', 'unknown')
        agent_name = alert.get('agent', {}).get('name', 'unknown')
        agent_os = 'windows' if 'windows' in agent_name.lower() or 'desktop' in agent_name.lower() else 'linux'
        
        recommended_action = ai_analysis.get('recommended_action', 'log_only')
        action_target = ai_analysis.get('action_target', 'unknown')
        
        log(f"Remediation requested: Action={recommended_action}, Target={action_target}, OS={agent_os}")
        
        # Validate action is allowed
        if recommended_action not in ALLOWED_ACTIONS:
            log(f"Action '{recommended_action}' not in allowlist: {ALLOWED_ACTIONS}")
            return jsonify({
                'success': False,
                'reason': 'Action not in allowlist'
            }), 403
        
        # Execute the action
        result = actions.execute_action(recommended_action, action_target, agent_os)
        
        log(f"Remediation result: {result}")
        
        # Send to verification
        try:
            requests.post(
                'http://verification:5000/verify',
                json={
                    'alert': alert,
                    'action': recommended_action,
                    'target': action_target,
                    'result': result
                },
                timeout=30
            )
        except Exception as e:
            log(f"Error sending to verification: {e}")
        
        return jsonify(result), 200
        
    except Exception as e:
        log(f"Error in remediate endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/rollback', methods=['POST'])
def rollback():
    """Rollback a remediation action"""
    try:
        data = request.json
        action_name = data.get('action')
        target = data.get('target')
        agent_os = data.get('agent_os', 'linux')
        
        log(f"Rollback requested: {action_name} for {target}")
        
        result = actions.rollback_action(action_name, target, agent_os)
        
        return jsonify(result), 200
        
    except Exception as e:
        log(f"Error in rollback endpoint: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    log("Remediation Engine service starting")
    log(f"Allowed actions: {ALLOWED_ACTIONS}")
    log(f"Windows host: {WINDOWS_HOST}")
    log(f"Linux host: {LINUX_HOST}")
    
    app.run(host='0.0.0.0', port=5000, debug=False)