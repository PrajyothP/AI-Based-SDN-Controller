from flask import Flask, request, jsonify
from ai_pipeline import AIPipeline
import logging
import os
import requests
import json
import re
from collections import deque

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
pipeline = None

LLM_DECISION_HISTORY = deque(maxlen=10)

OLLAMA_HOST_IP = "192.168.64.1"
OLLAMA_API_URL = f"http://{OLLAMA_HOST_IP}:11434/api/generate"

FEW_SHOT_PROMPT_TEMPLATE = """
[INST]
As an expert SDN security analyst, your task is to generate a simple, pipe-separated mitigation rule for each alert. Your response must be only the rules and nothing else.

**Rule Format and Logic:**
- Generate one rule per line in the format: `ACTION | parameter=value | ...`
- **Use the AI's confidence score to decide the action's severity:**
  - **High-Confidence Threat (>85%):** Use an aggressive action like `BLOCK_IP`.
  - **Medium-Confidence Threat (60-85%):** Use a firm action like `RATE_LIMIT_HIGH`.
  - **Low-Confidence Threat (<60%):** Use a cautious action like `RATE_LIMIT_LOW`.
- **Use the Recent Mitigation History to identify repeat offenders.** If you see the same IP in the history, consider escalating the action (e.g., from `RATE_LIMIT` to `BLOCK_IP`).

---
**== Alert Examples and Your Corresponding Responses ==**

**Alert:** "High-confidence (98%) DDoS attack detected from source IP 10.0.0.16."
**Your Response:**
BLOCK_IP | src_ip=10.0.0.16 | priority=40000

**Alert:** "Medium-confidence (75%) DDoS attack detected from source IP 10.0.0.17."
**Your Response:**
RATE_LIMIT_HIGH | src_ip=10.0.0.17 | rate_mbps=5 | priority=30000

**Alert:** "Low-confidence (55%) congestion detected for flow from 10.0.0.4 to 10.0.0.12."
**Your Response:**
RATE_LIMIT_LOW | src_ip=10.0.0.4 | dst_ip=10.0.0.12 | rate_mbps=50

---
**== Multi-Alert Example ==**
Alerts:
1. "Medium-confidence (65%) DDoS attack detected from source IP 10.0.0.17."
2. "High-confidence (95%) congestion detected for flow from 10.0.0.3 to 10.0.0.15."

Your Response:
RATE_LIMIT_HIGH | src_ip=10.0.0.17 | rate_mbps=5
AGGRESSIVE_DROP | src_ip=10.0.0.3 | dst_ip=10.0.0.15 | rate_mbps=2

---
**== Recent Mitigation History (Last 10 Actions) ==**
{mitigation_history}

---
Now, follow all instructions above to generate one simple, pipe-separated rule for each of the following alerts.

**Current Alerts:**
{alert_summary}
[/INST]
"""

def parse_simple_rule_format(line: str):
    try:
        # --- FIX: Sanitize the line to remove conversational filler before parsing ---
        # This regex removes patterns like "Rule 1:", "**Rule 1:** ", "1. ", etc. from the start.
        sanitized_line = re.sub(r'^\s*(\*\*Rule\s*\d+:\*\*|Rule\s*\d+:|\d+\.)\s*', '', line, flags=re.IGNORECASE).strip()

        parts = [p.strip() for p in sanitized_line.split('|')]
        if not parts or len(parts) < 2:
            return None
        
        action = parts[0]
        details = {}
        for param in parts[1:]:
            if '=' not in param: continue
            key, value = param.split('=', 1)
            key = key.strip()
            value = value.strip()
            if value.isdigit():
                details[key] = int(value)
            else:
                try:
                    details[key] = float(value)
                except ValueError:
                    details[key] = value
        
        return {"action": action, "details": details}
    except Exception as e:
        logging.error(f"Failed to parse simple rule format for line: '{line}'. Error: {e}")
        return None


def validate_and_correct_llm_rule(rule, actual_src_ip, actual_dst_ip):
    VALID_ACTIONS = {"BLOCK_IP", "RATE_LIMIT_LOW", "RATE_LIMIT_HIGH", "REROUTE_AND_RATE_LIMIT", "AGGRESSIVE_DROP"}
    
    if not isinstance(rule, dict) or "action" not in rule or "details" not in rule:
        logging.error(f"Rule validation failed: Missing 'action' or 'details'. Rule: {rule}")
        return None

    if rule['action'] not in VALID_ACTIONS:
        logging.error(f"Rule validation failed: Invalid action '{rule['action']}'.")
        return None

    details = rule['details']
    clean_details = {}
    if 'src_ip' not in details:
        logging.warning(f"LLM response did not include src_ip. Manually adding from context: {actual_src_ip}")
    clean_details['src_ip'] = actual_src_ip

    if actual_dst_ip != 'N/A' and 'dst_ip' in details:
         clean_details['dst_ip'] = details['dst_ip']

    if 'rate_mbps' in details:
        clean_details['rate_mbps'] = details['rate_mbps']
    if 'priority' in details:
        clean_details['priority'] = details['priority']
    if 'idle_timeout' in details:
        clean_details['idle_timeout'] = details['idle_timeout']
        
    validated_rule = {"action": rule['action'], "details": clean_details}
    logging.info(f"LLM response successfully parsed and validated. Final rule: {json.dumps(validated_rule, indent=2)}")
    return validated_rule

def call_llm(prompt: str, flows_for_validation: list, is_priming=False):
    global LLM_DECISION_HISTORY
    try:
        if is_priming:
            logging.info("Sending priming prompt to Large Language Model.")
            final_prompt = prompt
        else:
            logging.info(f"Generating mitigation rules via LLM for {len(flows_for_validation)} alerts.")
            history_str = "\n".join([f"- {item['action']} | {' | '.join([f'{k}={v}' for k, v in item['details'].items()])}" for item in LLM_DECISION_HISTORY]) if LLM_DECISION_HISTORY else "No recent actions taken."
            final_prompt = FEW_SHOT_PROMPT_TEMPLATE.format(alert_summary=prompt, mitigation_history=history_str)

        payload = {"model": "gemma:2b", "prompt": final_prompt, "stream": False, "options": {"temperature": 0.1}}
        response = requests.post(OLLAMA_API_URL, data=json.dumps(payload), timeout=120)
        response.raise_for_status()
        llm_response_text = response.json().get('response', '')

        if is_priming:
            logging.info("LLM priming successfully completed.")
            return None
        
        parsed_rules = []
        lines = llm_response_text.strip().split('\n')
        for line in lines:
            if line:
                rule = parse_simple_rule_format(line)
                if rule:
                    parsed_rules.append(rule)
        
        if not parsed_rules:
            logging.error(f"LLM response parsing error: Could not extract any valid rules. Full response: {llm_response_text.strip()}")
            return None

        validated_rules = []
        if len(parsed_rules) != len(flows_for_validation):
            logging.warning(f"LLM returned {len(parsed_rules)} rules for {len(flows_for_validation)} alerts. Proceeding with caution.")

        for i, rule in enumerate(parsed_rules):
            if i >= len(flows_for_validation): break
            validation_context = flows_for_validation[i]
            flow_info = validation_context['flow']
            actual_src = flow_info.get('src_ip', 'N/A')
            actual_dst = flow_info.get('dst_ip', 'N/A')
            
            validated_rule = validate_and_correct_llm_rule(rule, actual_src, actual_dst)
            if validated_rule:
                validated_rules.append(validated_rule)
        
        if validated_rules:
            for rule in validated_rules:
                LLM_DECISION_HISTORY.append(rule)
            logging.info(f"LLM decision history updated with {len(validated_rules)} new rules. Current history size: {len(LLM_DECISION_HISTORY)} decisions.")
        
        return validated_rules

    except Exception as e:
        logging.error(f"An exception occurred during communication with the Ollama LLM API: {e}")
        return None

def load_pipeline():
    global pipeline
    if pipeline is None:
        logging.info("Attempting to initialize the AI/ML analysis pipeline...")
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(base_dir, 'models')
            pipeline = AIPipeline(model_dir=model_path)
            logging.info("AI/ML analysis pipeline has been loaded and initialized successfully.")
        except Exception as e:
            logging.error(f"Fatal Error: Failed to load the AI/ML analysis pipeline. The service may not function correctly. Error: {e}", exc_info=True)
            pipeline = None
    return pipeline

@app.route('/analyze', methods=['POST'])
def analyze():
    ai_pipeline = load_pipeline()
    if not ai_pipeline:
        return jsonify({'error': 'AI pipeline is not available.'}), 503

    try:
        data = request.get_json()
        flow_batch = data.get('flows')
        if not isinstance(flow_batch, list):
            return jsonify({'error': 'Invalid payload: "flows" must be a list.'}), 400
        
        results = ai_pipeline.analyze_flow_batch(flow_batch)
        
        response_payload = {'results': results}
        actionable_rules = []
        flows_for_llm = []

        for i, res in enumerate(results):
            flow = flow_batch[i]
            if res['label'] == 'DDOS' and res['confidence'] > 0.90:
                logging.critical(f"High-Confidence DDoS (>90%) detected from {flow.get('src_ip', 'N/A')}. Applying direct block rule.")
                hard_rule = { "action": "BLOCK_IP", "details": { "src_ip": flow.get('src_ip', 'N/A'), "priority": 45000, "idle_timeout": 60 } }
                actionable_rules.append(hard_rule)
                LLM_DECISION_HISTORY.append(hard_rule)
            elif res['label'] in ['DDOS', 'CONGESTION']:
                flows_for_llm.append({'flow': flow, 'result': res})
        
        if flows_for_llm:
            flows_for_llm.sort(key=lambda x: (x['result']['label'] != 'DDOS', 1 - x['result']['confidence']))
            
            top_flows_to_process = flows_for_llm[:5]
            alerts_for_llm = []
            flow_data_for_validation = []
            
            for idx, item in enumerate(top_flows_to_process):
                flow = item['flow']
                res = item['result']
                confidence_percent = res['confidence'] * 100
                src_ip = flow.get('src_ip', 'N/A')
                dst_ip = flow.get('dst_ip', 'N/A')
                threat_label = "DDoS attack" if res['label'] == 'DDOS' else "congestion"
                
                if res['label'] == 'DDOS': 
                    if confidence_percent > 85: conf_level = "High-confidence"
                    elif confidence_percent > 60: conf_level = "Medium-confidence"
                    else: conf_level = "Low-confidence"
                else: # Congestion
                    if confidence_percent > 80: conf_level = "High-confidence"
                    elif confidence_percent > 40: conf_level = "Moderate-confidence"
                    else: conf_level = "Low-confidence"
                
                alert_text = (f"{idx+1}. {conf_level} ({confidence_percent:.0f}%) {threat_label} detected from source IP {src_ip} to destination IP {dst_ip}.")
                alerts_for_llm.append(alert_text)
                flow_data_for_validation.append({'flow': flow, 'result': res})

            alert_summary_string = "\n".join(alerts_for_llm)
            llm_rules = call_llm(alert_summary_string, flows_for_validation=flow_data_for_validation)
            
            if llm_rules:
                actionable_rules.extend(llm_rules)

        if actionable_rules:
            response_payload['actionable_rules'] = actionable_rules
        
        return jsonify(response_payload)

    except Exception as e:
        logging.error(f"An unexpected error occurred during the analysis request: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
def prime_llm_with_context():
    topology_description = """
    Memorize the following network topology for all future requests. This is the environment you are managing.
    - There are 6 switches (s1 to s6) connected in a linear chain: s1-s2-s3-s4-s5-s6.
    - There are 18 hosts (h1 to h18).
    - Hosts h1, h2, h3 are connected to switch s1.
    - Hosts h4, h5, h6 are connected to switch s2.
    - Hosts h7, h8, h9 are connected to switch s3.
    - Hosts h10, h11, h12 are connected to switch s4.
    - Hosts h13, h14, h15 are connected to switch s5.
    - Hosts h16, h17, h18 are connected to switch s6.
    - Host IPs range from 10.0.0.1 (h1) to 10.0.0.18 (h18).
    Acknowledge that you have understood the topology.
    """
    call_llm(prompt=f"[INST] {topology_description} [/INST]", is_priming=True, flows_for_validation=[])

if __name__ == '__main__':
    load_pipeline()
    print("-------------------------------------------------------")
    print("Starting AI/LLM API Server...")
    print(f"   - Listening on: http://0.0.0.0:5000")
    print(f"   - Analysis endpoint: /analyze")
    print(f"   - Ollama LLM API target: {OLLAMA_API_URL}")
    print("-------------------------------------------------------")
    prime_llm_with_context()
    app.run(host='0.0.0.0', port=5000)