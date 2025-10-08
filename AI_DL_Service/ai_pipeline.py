import keras
import joblib
import pickle
import numpy as np
import os
import pandas as pd
import warnings

# Suppress the specific UserWarning from sklearn about feature names
warnings.filterwarnings("ignore", message="X does not have valid feature names, but MinMaxScaler was fitted with feature names")

# NEW: Added the port encoding logic as requested
# ==============================================================================
web = [80,443]
dns = [53]
risky = set([4444, 5554, 6666, 6667, 6668, 6669, 31337, 12345, 54321, 135, 139, 445, 8080, 8888, 9000, 17, 19])
# Add private/ephemeral ports to risky set
for p in range(49152, 65536):
  risky.add(p)

well_known = set(v for v in range(1024) if v not in risky and v not in web and v not in dns)
registered = set(v for v in range(1024, 49152) if v not in risky)

def encode_port(port):
  if port in web:
    return 1 # Web
  elif port in dns:
    return 2 # DNS
  elif port in well_known:
    return 3 # Well-known (Safe)
  elif port in registered:
    return 4 # Registered (User)
  elif port in risky:
    return 5 # Risky / Ephemeral
  else:
    return 5 # Default to risky if somehow uncategorized
# ==============================================================================


AE_FEATURES_ORDER = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Packet Length Mean"
]

DDoS_FEATURES_ORDER = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Flow Packets/s"
]

class AIPipeline:
    def __init__(self, model_dir_relative='models/'):
        script_dir = os.path.dirname(os.path.realpath(__file__))
        model_dir = os.path.join(script_dir, model_dir_relative)
        try:
            self.autoencoder = keras.models.load_model(os.path.join(model_dir, 'autoencoder_model.keras'))
            self.ddos_model = keras.models.load_model(os.path.join(model_dir, 'ddos_model.keras'))
            self.forest_embedder = joblib.load(os.path.join(model_dir, 'forest_embedder.joblib'))
            self.ddos_scaler = joblib.load(os.path.join(model_dir, 'ddos_scaler.joblib'))
            self.unified_ae_scaler = joblib.load(os.path.join(model_dir, 'unified_ae_scaler.pkl'))
            with open(os.path.join(model_dir, 'unified_threshold.pkl'), 'rb') as f: self.ae_threshold = pickle.load(f)
            with open(os.path.join(model_dir, 'forest_emb_max.pkl'), 'rb') as f: self.forest_emb_max = pickle.load(f)
            print("✅ AI Pipeline initialized successfully with all components.")
        except FileNotFoundError as e:
            print(f"FATAL ERROR: A required model file was not found. Searched in: {model_dir}")
            print(f"Original error: {e}")
            raise
        except Exception as e:
            print(f"FATAL ERROR loading AI models: {e}")
            raise

    def analyze_flow_batch(self, flow_batch: list):
        if not flow_batch:
            return []

        num_flows = len(flow_batch)
        default_result = {'label': 'NORMAL', 'probability': 0.0}
        results = [default_result] * num_flows

        try:
            # NEW: Create a copy of the flow batch to encode the destination port for the autoencoder
            ae_flow_batch = []
            for flow in flow_batch:
                flow_copy = flow.copy()
                flow_copy['Destination Port'] = encode_port(flow_copy['Destination Port'])
                ae_flow_batch.append(flow_copy)

            # Use the encoded batch to create the DataFrame for the autoencoder
            df_for_ae = pd.DataFrame(ae_flow_batch)[AE_FEATURES_ORDER]
            
            ae_batch_scaled = self.unified_ae_scaler.transform(df_for_ae)
            reconstructed_batch = self.autoencoder.predict(ae_batch_scaled, verbose=0)
            errors = np.mean(np.square(ae_batch_scaled - reconstructed_batch), axis=1)
            anomalous_indices = np.where(errors > self.ae_threshold)[0]
            
            if anomalous_indices.size == 0:
                return results

            print(f"⚠️  {len(anomalous_indices)} anomalous flows detected for Stage 2 analysis.")
        
        except Exception as e:
            print(f"❌ Error during batch anomaly detection: {e}")
            return [{'label': 'ANALYSIS_ERROR', 'probability': 0.0}] * num_flows

        try:
            # The DDoS stage uses the ORIGINAL flow_batch, as it does not use the port feature.
            ddos_sub_batch = [flow_batch[i] for i in anomalous_indices]
            
            df_input = pd.DataFrame(ddos_sub_batch)
            X_input = df_input[DDoS_FEATURES_ORDER].replace([np.inf, -np.inf], 0.0).fillna(0.0)
            X_scaled = self.ddos_scaler.transform(X_input)
            X_emb = self.forest_embedder.apply(X_scaled).astype(np.float32)
            safe_divisor = np.where(self.forest_emb_max == 0, 1.0, self.forest_emb_max)
            X_emb /= safe_divisor
            prediction_probs = self.ddos_model.predict(X_emb, verbose=0)

            for i, idx in enumerate(anomalous_indices):
                prob = prediction_probs[i][0]
                if prob > 0.3:
                    results[idx] = {'label': 'DDOS', 'probability': float(prob)}
                else:
                    results[idx] = {'label': 'CONGESTION', 'probability': float(prob)}
            
            return results

        except Exception as e:
            print(f"❌ Error during batch DDoS classification: {e}")
            for idx in anomalous_indices:
                results[idx] = {'label': 'ANALYSIS_ERROR', 'probability': 0.0}
            return results