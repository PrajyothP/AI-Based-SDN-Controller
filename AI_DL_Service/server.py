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
As an expert SDN security analyst, your task is to generate a JSON array of flow rules, one for each alert provided below. The rule for each alert must be a specific, actionable mitigation. Your response must be only the JSON array and nothing else.

**Rule Format:**
- The JSON object must contain "action" and "details".
- "action" can be: "BLOCK_IP", "RATE_LIMIT_LOW", "RATE_LIMIT_HIGH", "REROUTE_AND_RATE_LIMIT", or "AGGRESSIVE_DROP".
- "details" must contain the specific parameters for the action.

---
**== DDoS Examples ==**

**Example 1: High-Confidence DDoS Attack (>60%)**
Alert: "High-confidence (98%) DDoS attack detected from source IP 10.0.0.16."
Your JSON Response:
{{
  "action": "BLOCK_IP",
  "details": {{
    "src_ip": "10.0.0.16",
    "priority": 40000,
    "idle_timeout": 60
  }}
}}

**Example 2: Low-Confidence DDoS Attack (<60%)**
Alert: "Low-confidence (55%) DDoS attack detected from source IP 10.0.0.17."
Your JSON Response:
{{
  "action": "RATE_LIMIT_HIGH",
  "details": {{
    "src_ip": "10.0.0.17",
    "rate_mbps": 5,
    "priority": 30000
  }}
}}

---
**== Congestion Examples ==**

**Example 3: Severe Congestion (80-100%)**
Alert: "High-confidence (95%) congestion detected for flow from 10.0.0.2 to 10.0.0.18."
Your JSON Response:
{{
  "action": "AGGRESSIVE_DROP",
  "details": {{
    "src_ip": "10.0.0.2",
    "dst_ip": "10.0.0.18",
    "rate_mbps": 2,
    "priority": 20000
  }}
}}

**Example 4: Moderate Congestion (40-80%)**
Alert: "Moderate-confidence (65%) congestion detected for flow from 10.0.0.3 to 10.0.0.15."
Your JSON Response:
{{
  "action": "REROUTE_AND_RATE_LIMIT",
  "details": {{
    "src_ip": "10.0.0.3",
    "dst_ip": "10.0.0.15",
    "rate_mbps": 10
  }}
}}

**Example 5: Low-Level Congestion (0-40%)**
Alert: "Low-confidence (25%) congestion detected for flow from 10.0.0.4 to 10.0.0.12."
Your JSON Response:
{{
  "action": "RATE_LIMIT_LOW",
  "details": {{
    "src_ip": "10.0.0.4",
    "dst_ip": "10.0.0.12",
    "rate_mbps": 50
  }}
}}

---
**== Multi-Alert Example ==**

Alerts:
1. "Low-confidence (55%) DDoS attack detected from source IP 10.0.0.17."
2. "Moderate-confidence (65%) congestion detected for flow from 10.0.0.3 to 10.0.0.15."

Your JSON Response:
[
  {{
    "action": "RATE_LIMIT_HIGH",
    "details": {{
      "src_ip": "10.0.0.17",
      "rate_mbps": 5,
      "priority": 30000
    }}
  }},
  {{
    "action": "REROUTE_AND_RATE_LIMIT",
    "details": {{
      "src_ip": "10.0.0.3",
      "dst_ip": "10.0.0.15",
      "rate_mbps": 10
    }}
  }}
]

---
**== Recent Mitigation History (Last 10 Actions) ==**
{mitigation_history}

---
Now, based on the examples AND the recent history above, generate the appropriate JSON array of rules for the following alerts. Pay close attention to repeat offenders in the history.
Your response must be only the JSON array and nothing else.

**Current Alerts:**
{alert_summary}
[/INST]
"""

def validate_and_correct_llm_rule(rule, actual_src_ip, actual_dst_ip):
    VALID_ACTIONS = {"BLOCK_IP", "RATE_LIMIT_LOW", "RATE_LIMIT_HIGH", "REROUTE_AND_RATE_LIMIT", "AGGRESSIVE_DROP"}
    if not isinstance(rule, dict) or "action" not in rule or "details" not in rule:
        logging.error(f"LLM Response Validation Failed: Rule is missing 'action' or 'details' keys. Rule content: {rule}")
        return None
    if not isinstance(rule['details'], dict):
        logging.error(f"LLM Response Validation Failed: The 'details' key does not contain a dictionary. Rule content: {rule}")
        return None

    if rule['action'] not in VALID_ACTIONS:
        if rule['action'].upper() == "BLACKLIST":
            rule['action'] = "BLOCK_IP"
        else:
            logging.error(f"LLM Response Validation Failed: Invalid action '{rule['action']}' provided.")
            return None

    details = rule['details']
    clean_details = {}
    if 'src_ip' not in details or details['src_ip'] != actual_src_ip:
        logging.warning(f"Correcting mismatched source IP in LLM response. Alert IP: '{actual_src_ip}', LLM IP: '{details.get('src_ip')}'. Overwriting with actual source IP.")
    clean_details['src_ip'] = actual_src_ip
    if 'dst_ip' in details and details['dst_ip'] != actual_dst_ip:
        logging.warning(f"Correcting mismatched destination IP in LLM response. Alert IP: '{actual_dst_ip}', LLM IP: '{details.get('dst_ip')}'. Overwriting with actual destination IP.")
    if actual_dst_ip != 'N/A':
         clean_details['dst_ip'] = actual_dst_ip

    if 'rate_mbps' in details and isinstance(details['rate_mbps'], (int, float)):
        clean_details['rate_mbps'] = details['rate_mbps']
    priority = details.get('priority', details.get('prsion'))
    if priority and isinstance(priority, int):
        clean_details['priority'] = priority
    if 'idle_timeout' in details and isinstance(details['idle_timeout'], int):
        clean_details['idle_timeout'] = details['idle_timeout']
        
    validated_rule = {"action": rule['action'], "details": clean_details}
    logging.info(f"LLM response successfully validated and sanitized. Final rule: {json.dumps(validated_rule, indent=2)}")
    return validated_rule

def call_llm(prompt: str, flows_for_validation: list, is_priming=False):
    global LLM_DECISION_HISTORY
    try:
        if is_priming:
            logging.info("Sending priming prompt to Large Language Model with network topology context.")
            final_prompt = prompt
        else:
            logging.info(f"Generating mitigation rules via LLM for {len(flows_for_validation)} alerts.")
            if not LLM_DECISION_HISTORY:
                history_str = "No recent actions taken."
            else:
                history_entries = [f"- Action: {item['action']}, Details: {item['details']}" for item in LLM_DECISION_HISTORY]
                history_str = "\n".join(history_entries)
            final_prompt = FEW_SHOT_PROMPT_TEMPLATE.format(alert_summary=prompt, mitigation_history=history_str)

        payload = {"model": "gemma:2b", "prompt": final_prompt, "stream": False, "options": {"temperature" : 0.2}}
        response = requests.post(OLLAMA_API_URL, data=json.dumps(payload), timeout=120)
        response.raise_for_status()
        llm_response_text = response.json().get('response', '[]')

        if is_priming:
            logging.info("LLM priming successfully completed.")
            return None
        
        json_match = re.search(r'\[.*\]', llm_response_text, re.DOTALL)
        if not json_match:
            logging.error(f"LLM response parsing error: No valid JSON array found in the response text. Full response: {llm_response_text.strip()}")
            return None

        json_string = json_match.group(0)
        validated_rules = []
        try:
            parsed_rules = json.loads(json_string)
            if not isinstance(parsed_rules, list):
                logging.error(f"LLM did not return a list. Response: {parsed_rules}")
                return None
            
            if len(parsed_rules) != len(flows_for_validation):
                logging.warning(f"LLM returned {len(parsed_rules)} rules for {len(flows_for_validation)} alerts. Proceeding with caution.")

            for i, rule in enumerate(parsed_rules):
                if i >= len(flows_for_validation): break
                flow_info = flows_for_validation[i]
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
        except json.JSONDecodeError as e:
            logging.error(f"JSON Decode Error: Failed to parse the extracted JSON array from LLM response. String was: '{json_string.strip()}'. Error details: {e}")
            return None

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
                hard_rule = {
                    "action": "BLOCK_IP",
                    "details": {
                        "src_ip": flow.get('src_ip', 'N/A'),
                        "priority": 45000,
                        "idle_timeout": 60
                    }
                }
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
                    conf_level = "High-confidence" if confidence_percent > 60 else "Low-confidence"
                else:
                    if confidence_percent > 80: conf_level = "High-confidence"
                    elif confidence_percent > 40: conf_level = "Moderate-confidence"
                    else: conf_level = "Low-confidence"
                
                alert_text = (
                    f"{idx+1}. {conf_level} ({confidence_percent:.0f}%) {threat_label} detected "
                    f"from source IP {src_ip} to destination IP {dst_ip}."
                )
                alerts_for_llm.append(alert_text)
                flow_data_for_validation.append(flow)

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