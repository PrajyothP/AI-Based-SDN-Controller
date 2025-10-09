import keras
import joblib
import logging
import pickle
import numpy as np
import os
import pandas as pd

# Define the feature names for clarity and order
AE_FEATURES_ORDER = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Packet Length Mean"
]

DDoS_FEATURES_ORDER = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Flow Packets/s"
]

# --- Port Encoding Logic ---
WEB_PORTS = {80, 443}
DNS_PORTS = {53}
# Ports commonly associated with exploits or botnets
RISKY_PORTS = {4444, 5554, 6666, 6667, 6668, 6669, 31337, 12345, 54321, 135, 139, 445, 8080, 8888, 9000, 17, 19}
RISKY_PORTS.update(range(49152, 65536)) # Ephemeral/private ports can also be risky

WELL_KNOWN_PORTS = {p for p in range(1024) if p not in RISKY_PORTS and p not in WEB_PORTS and p not in DNS_PORTS}
REGISTERED_PORTS = {p for p in range(1024, 49152) if p not in RISKY_PORTS}

def encode_port(port):
    """Encodes a port number into a categorical feature."""
    if port in WEB_PORTS:
        return 1  # Web traffic
    elif port in DNS_PORTS:
        return 2  # DNS traffic
    elif port in WELL_KNOWN_PORTS:
        return 3  # Other well-known service
    elif port in REGISTERED_PORTS:
        return 4  # Registered port range
    else: # This will catch ports in RISKY_PORTS
        return 5  # Risky or private port

class AIPipeline:
    def __init__(self, model_dir=None):
        """Initializes the AI pipeline by loading all models and scalers."""
        try:
            if model_dir is None:
                base_dir = os.path.dirname(os.path.abspath(__file__))
                model_dir = os.path.join(base_dir, 'models')

            self.autoencoder = keras.models.load_model(os.path.join(model_dir, 'autoencoder_model.keras'))
            
            with open(os.path.join(model_dir, 'unified_threshold.pkl'), 'rb') as f:
                self.ae_threshold = pickle.load(f)

            self.ae_scaler = joblib.load(os.path.join(model_dir, 'unified_ae_scaler.pkl'))

            self.ddos_model = keras.models.load_model(os.path.join(model_dir, 'ddos_model.keras'))
            self.forest_embedder = joblib.load(os.path.join(model_dir, 'forest_embedder.joblib'))
            self.ddos_scaler = joblib.load(os.path.join(model_dir, 'ddos_scaler.joblib'))
            
            with open(os.path.join(model_dir, 'forest_emb_max.pkl'), 'rb') as f:
                self.forest_emb_max = pickle.load(f)
            
            print("✅ AI Pipeline initialized successfully with all components.")
        except FileNotFoundError as e:
            print(f"FATAL ERROR: A required model file was not found: {e}")
            raise
        except Exception as e:
            print(f"FATAL ERROR loading AI models: {e}")
            raise
        
    def analyze_flow_batch(self, flow_batch: list):
        """
        Analyzes a batch of flows and returns a list of dictionaries, 
        each containing the classification and confidence.
        """
        if not flow_batch:
            return []

        num_flows = len(flow_batch)
        # Initialize results as a list of dictionaries
        results = [{"label": "NORMAL", "confidence": 0.0} for _ in range(num_flows)]

        try:
            df_ae = pd.DataFrame(flow_batch, columns=AE_FEATURES_ORDER)
            
            # --- Preprocessing for Autoencoder ---
            df_ae['Destination Port'] = df_ae['Destination Port'].apply(encode_port)
            log_features = [
                "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
                "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Packet Length Mean"
            ]
            for col in log_features:
                df_ae[col] = np.log1p(df_ae[col].clip(lower=0))

            ae_batch_scaled = self.ae_scaler.transform(df_ae)
            
            reconstructed_batch = self.autoencoder.predict(ae_batch_scaled, verbose=0)
            errors = np.mean(np.square(ae_batch_scaled - reconstructed_batch), axis=1)

            # For normal flows, confidence is how far below the threshold the error is
            for i, error in enumerate(errors):
                if error <= self.ae_threshold:
                    confidence = 1.0 - (error / self.ae_threshold)
                    results[i]["confidence"] = float(confidence)

            anomalous_indices = np.where(errors > self.ae_threshold)[0]
            if anomalous_indices.size == 0:
                return results

            print(f"⚠️  {len(anomalous_indices)} anomalous flows detected for Stage 2 analysis.")
        
        except Exception as e:
            print(f"❌ Error during batch anomaly detection: {e}")
            return [{"label": "ANALYSIS_ERROR", "confidence": 1.0}] * num_flows

        try:
            ddos_sub_batch = [flow_batch[i] for i in anomalous_indices]
            df_input = pd.DataFrame(ddos_sub_batch)
            X_input = df_input[DDoS_FEATURES_ORDER].replace([np.inf, -np.inf], 0.0).fillna(0.0)

            X_scaled = self.ddos_scaler.transform(X_input)
            X_emb = self.forest_embedder.apply(X_scaled).astype(np.float32)
            X_emb /= (self.forest_emb_max + 1e-9)

            prediction_probs = self.ddos_model.predict(X_emb, verbose=0)

            for i, idx in enumerate(anomalous_indices):
                ddos_prob = prediction_probs[i][0]
                if ddos_prob > 0.5:
                    results[idx] = {"label": "DDOS", "confidence": float(ddos_prob)}
                else:
                    # Confidence for congestion is 1 minus the DDoS probability
                    results[idx] = {"label": "CONGESTION", "confidence": 1.0 - float(ddos_prob)}
            
            return results

        except Exception as e:
            print(f"❌ Error during batch DDoS classification: {e}")
            for idx in anomalous_indices:
                results[idx] = {"label": "ANALYSIS_ERROR", "confidence": 1.0}
            return results