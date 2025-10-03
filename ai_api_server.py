# api_server.py

from flask import Flask, request, jsonify
from ryu_app.ai_pipeline import AIPipeline
import logging

# Set up logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR) # Suppress standard Flask request logs for cleaner output

app = Flask(__name__)

# --- Load the AI Pipeline ONCE at startup ---
print("🚀 Initializing AI Pipeline for API server...")
try:
    ai_pipeline = AIPipeline(model_dir='models/')
    print("✅ AI Pipeline loaded successfully.")
except Exception as e:
    print(f"🔥 FATAL: Could not initialize AI Pipeline: {e}")
    ai_pipeline = None

@app.route('/analyze', methods=['POST'])
def analyze():
    if ai_pipeline is None:
        return jsonify({"error": "AI Pipeline not initialized"}), 500

    flow_batch = request.json.get('flows')
    if not flow_batch:
        return jsonify({"error": "Missing 'flows' data"}), 400

    try:
        results = ai_pipeline.analyze_flow_batch(flow_batch)
        # Log the analysis results on the server side
        num_ddos = results.count("DDOS")
        num_cong = results.count("CONGESTION")
        print(f"🧠 Analysis complete: DDoS={num_ddos}, Congestion={num_cong}, Normal={results.count('NORMAL')}")
        return jsonify({"results": results})
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        return jsonify({"error": "An error occurred during analysis"}), 500

if __name__ == '__main__':
    print("🔥 Starting AI API Server on http://127.0.0.1:5000")
    # Use the VM's main IP to be accessible from Ryu
    app.run(host='0.0.0.0', port=5000, debug=False)