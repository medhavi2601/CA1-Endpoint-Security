from flask import Flask, request, jsonify
import requests
import json
from datetime import datetime

app = Flask(__name__)

LOG_FILE = '/app/logs/ai_analyzer.log'

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    with open(LOG_FILE, 'a') as f:
        f.write(log_msg + '\n')

def analyze_alert_with_ollama(alert_data):
    """Use Ollama (local LLM) to classify alert severity"""
    
    try:
        alert_summary = f"""
        Analyze this security alert and classify its severity (low/medium/high/critical):
        
        Rule ID: {alert_data.get('rule', {}).get('id', 'unknown')}
        Description: {alert_data.get('rule', {}).get('description', 'No description')}
        Level: {alert_data.get('rule', {}).get('level', 0)}
        Agent: {alert_data.get('agent', {}).get('name', 'unknown')}
        
        Respond with ONLY: low, medium, high, or critical
        """
        
        ollama_response = requests.post(
            'http://host.docker.internal:11434/api/generate',
            json={
                'model': 'llama3.2:1b',
                'prompt': alert_summary,
                'stream': False
            },
            timeout=10
        )
        
        if ollama_response.status_code == 200:
            ai_response = ollama_response.json()
            severity = ai_response.get('response', '').strip().lower()
            
            valid_severities = ['low', 'medium', 'high', 'critical']
            if any(s in severity for s in valid_severities):
                for s in valid_severities:
                    if s in severity:
                        severity = s
                        break
            else:
                severity = 'medium'
            
            log(f"AI classified alert as: {severity}")
            return severity
        else:
            log(f"Ollama API error: {ollama_response.status_code}")
            return 'medium'
            
    except Exception as e:
        log(f"Error calling Ollama: {str(e)}")
        return 'medium'

@app.route('/analyze', methods=['POST'])
def analyze():
    """Receive alert and classify with AI"""
    
    try:
        alert = request.get_json()
        log(f"Received alert for analysis: {alert.get('rule', {}).get('id', 'unknown')}")
        
        severity = analyze_alert_with_ollama(alert)
        
        needs_remediation = severity in ['high', 'critical']
        
        suggested_action = 'log_only'
        if needs_remediation:
            rule_desc = alert.get('rule', {}).get('description', '').lower()
            if 'brute' in rule_desc or 'authentication' in rule_desc:
                suggested_action = 'block_ip'
            elif 'process' in rule_desc or 'suspicious' in rule_desc:
                suggested_action = 'kill_process'
        
        result = {
            'alert_id': alert.get('id', 'unknown'),
            'ai_severity': severity,
            'needs_remediation': needs_remediation,
            'suggested_action': suggested_action,
            'reasoning': f"AI classified as {severity} severity"
        }
        
        log(f"Analysis complete: {result}")
        return jsonify(result), 200
        
    except Exception as e:
        log(f"Error analyzing alert: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'ai_backend': 'ollama'}), 200

if __name__ == '__main__':
    log("AI Analyzer starting with Ollama backend...")
    app.run(host='0.0.0.0', port=5000)