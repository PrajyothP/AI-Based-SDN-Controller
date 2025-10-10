# AI-DL_Service/server.py

from flask import Flask, request, jsonify
from ai_pipeline import AIPipeline
import logging
import os
import requests
import json

# Configure basic logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
pipeline = None

# --- LLM Configuration ---
OLLAMA_HOST_IP = "192.168.64.1" # Based on your previous logs
OLLAMA_API_URL = f"http://{OLLAMA_HOST_IP}:11434/api/generate"

# --- ADVANCED FEW-SHOT PROMPT ---
# This prompt provides tiered examples for different threats and confidence levels.
FEW_SHOT_PROMPT_TEMPLATE = """
[INST]
As an expert SDN security analyst, your task is to generate a single, precise flow rule in JSON format based on a network alert. The rule must be a specific, actionable mitigation for the described threat. Your response must be only the JSON object and nothing else.

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
Now, based on the examples above, generate the appropriate JSON rule for the following alert.
Your response must be only the JSON object and nothing else.

**Current Alert:**
"{alert_summary}"
[/INST]
"""


def call_llm(prompt: str, is_priming=False):
    """Sends a prompt to the Ollama LLM."""
    try:
        if is_priming:
            logging.info("🧠 Priming LLM with network context...")
        else:
            logging.info(f"💬 Generating LLM prompt for alert...")
        
        final_prompt = prompt if is_priming else FEW_SHOT_PROMPT_TEMPLATE.format(alert_summary=prompt)
        
        payload = {"model": "tinyllama", "prompt": final_prompt, "stream": False}
        response = requests.post(OLLAMA_API_URL, data=json.dumps(payload), timeout=120)
        response.raise_for_status()
        llm_response = response.json().get('response', '{}')
        
        if not is_priming:
            print("\n--- LLM-GENERATED FLOW RULE ---")
            try:
                parsed_json = json.loads(llm_response)
                print(json.dumps(parsed_json, indent=2))
            except json.JSONDecodeError:
                print(llm_response.strip())
            print("---------------------------------\n")
        else:
            logging.info("✅ LLM priming complete.")
            
    except Exception as e:
        logging.error(f"❌ Error during LLM communication: {e}")


def load_pipeline():
    global pipeline
    if pipeline is None:
        logging.info("🚀 Initializing AI Pipeline...")
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(base_dir, 'models')
            pipeline = AIPipeline(model_dir=model_path)
            logging.info("✅ AI Pipeline loaded successfully.")
        except Exception as e:
            logging.error(f"💀 Failed to load AI pipeline: {e}", exc_info=True)
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
        
        # Find the most severe threat in the batch to report to the LLM
        most_severe_flow = None
        highest_confidence = 0
        threat_label = ""
        is_ddos = False

        for i, res in enumerate(results):
            if res['label'] == 'DDOS' and res['confidence'] > highest_confidence:
                highest_confidence = res['confidence']
                most_severe_flow = flow_batch[i]
                threat_label = "DDoS attack"
                is_ddos = True
            # Only consider congestion if a higher-confidence DDoS hasn't already been found
            elif res['label'] == 'CONGESTION' and not is_ddos:
                if res['confidence'] > highest_confidence:
                    highest_confidence = res['confidence']
                    most_severe_flow = flow_batch[i]
                    threat_label = "congestion"

        # If a threat was found, create a detailed alert and call the LLM
        if most_severe_flow:
            confidence_percent = highest_confidence * 100
            src_ip = most_severe_flow.get('src_ip', 'N/A')
            dst_ip = most_severe_flow.get('dst_ip', 'N/A')
            
            # Determine confidence level string
            if is_ddos:
                conf_level = "High-confidence" if confidence_percent > 60 else "Low-confidence"
            else: # Congestion
                if confidence_percent > 80: conf_level = "High-confidence"
                elif confidence_percent > 40: conf_level = "Moderate-confidence"
                else: conf_level = "Low-confidence"
            
            alert = (
                f"{conf_level} ({confidence_percent:.0f}%) {threat_label} detected "
                f"from source IP {src_ip} to destination IP {dst_ip}."
            )
            call_llm(alert)

        return jsonify({'results': results})

    except Exception as e:
        logging.error(f"❌ Error during analysis: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
def prime_llm_with_context():
    """Sends the network topology to the LLM once on startup."""
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
    call_llm(prompt=f"[INST] {topology_description} [/INST]", is_priming=True)

if __name__ == '__main__':
    load_pipeline()
    print(f"🔥 Starting AI/LLM API Server on http://0.0.0.0:5000")
    print(f"   - Analysis endpoint: /analyze")
    print(f"   - Will attempt to connect to Ollama at: {OLLAMA_API_URL}")
    prime_llm_with_context()
    app.run(host='0.0.0.0', port=5000)