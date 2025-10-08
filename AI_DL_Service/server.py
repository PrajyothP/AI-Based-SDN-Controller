from flask import Flask, request, jsonify
from ai_pipeline import AIPipeline
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# --- Global AI Pipeline Instance ---
pipeline = None

def load_pipeline():
    """Load the AI pipeline instance."""
    global pipeline
    if pipeline is None:
        logging.info("🚀 Initializing AI Pipeline for API server...")
        try:
            pipeline = AIPipeline()
            logging.info("✅ AI Pipeline loaded successfully.")
        except Exception as e:
            logging.error(f"💀 Failed to load AI pipeline: {e}", exc_info=True)
            pipeline = None # Ensure it's None if loading fails
    return pipeline

@app.route('/analyze', methods=['POST'])
def analyze():
    """API endpoint to analyze a batch of traffic flows."""
    ai_pipeline = load_pipeline()
    if not ai_pipeline:
        return jsonify({'error': 'AI pipeline is not available.'}), 503 # Service Unavailable

    try:
        data = request.get_json()
        
        # FIX: The key error was here. We must extract the list from the 'flows' key.
        # The controller sends a JSON object: {'flows': [flow1, flow2, ...]}
        flow_batch = data.get('flows')

        if not isinstance(flow_batch, list):
            return jsonify({'error': 'Invalid payload: "flows" key must contain a list.'}), 400

        # Pass the extracted list to the analysis function
        results = ai_pipeline.analyze_flow_batch(flow_batch)
        return jsonify({'results': results})

    except Exception as e:
        logging.error(f"❌ Error during analysis: {e}", exc_info=True)
        # This will return a 500 Internal Server Error, which is what the controller sees.
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    load_pipeline() # Load the model on startup
    print(f"🔥 Starting AI API Server on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000)