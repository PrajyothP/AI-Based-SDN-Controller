# AI-DL_Service/server.py

from flask import Flask, request, jsonify
from ai_pipeline import AIPipeline
import logging
import os

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
pipeline = None

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
        if not data or 'flows' not in data:
            return jsonify({'error': 'Invalid payload: Missing "flows" key.'}), 400
        
        results = ai_pipeline.analyze_flow_batch(data['flows'])
        
        labels = [r['label'] for r in results]
        logging.info(f"🧠 Analysis complete: DDoS={labels.count('DDOS')}, Congestion={labels.count('CONGESTION')}, Normal={labels.count('NORMAL')}")
        
        return jsonify({'results': results})

    except Exception as e:
        logging.error(f"❌ Error during analysis: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    load_pipeline()
    print(f"🔥 Starting AI API Server on http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000)