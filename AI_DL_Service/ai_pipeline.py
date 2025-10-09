# AI-DL_Service/ai_pipeline.py

import keras
import joblib
import pickle
import numpy as np
import os
import pandas as pd

# Feature set for the Autoencoder (Stage 1) - space-separated
AE_FEATURES_ORDER = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Packet Length Mean"
]

# --- FINAL FIX: Feature names for DDoS model are also space-separated ---
DDoS_FEATURES_ORDER = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Flow Packets/s"
]

def encode_port(port):
    if port in {80, 443}: return 1
    if port == 53: return 2
    if 0 <= port <= 1023: return 3
    if 1024 <= port <= 49151: return 4
    return 5

class AIPipeline:
    def __init__(self, model_dir='models/'):
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(base_dir, model_dir)

            # --- Stage 1: Load Autoencoder Components ---
            self.autoencoder = keras.models.load_model(os.path.join(model_path, 'autoencoder_model.keras'))
            with open(os.path.join(model_path, 'unified_threshold.pkl'), 'rb') as f:
                self.ae_threshold = pickle.load(f)
            self.ae_scaler = joblib.load(os.path.join(model_path, 'unified_ae_scaler.pkl'))

            # --- Stage 2: Load LightGBM DDoS Classifier Components ---
            self.ddos_model = joblib.load(os.path.join(model_path, 'ddos_model.joblib'))
            with open(os.path.join(model_path, 'ddos_features.pkl'), 'rb') as f:
                self.ddos_features = pickle.load(f) # This list should have space-separated names
            
            print("✅ AI Pipeline initialized successfully with Autoencoder and LightGBM models.")
        except Exception as e:
            print(f"FATAL ERROR loading AI models: {e}")
            raise

    def analyze_flow_batch(self, flow_batch: list):
        if not flow_batch: return []
        num_flows = len(flow_batch)
        results = [{"label": "NORMAL", "confidence": 0.0} for _ in range(num_flows)]
        df_full = pd.DataFrame(flow_batch)

        # --- Stage 1: Anomaly Detection with Autoencoder ---
        try:
            df_ae = df_full[AE_FEATURES_ORDER].copy()
            df_ae['Destination Port'] = df_ae['Destination Port'].apply(encode_port)
            log_features = AE_FEATURES_ORDER[1:]
            for col in log_features:
                df_ae[col] = np.log1p(df_ae[col].clip(lower=0))

            ae_batch_scaled = self.ae_scaler.transform(df_ae)
            reconstructed = self.autoencoder.predict(ae_batch_scaled, verbose=0)
            errors = np.mean(np.square(ae_batch_scaled - reconstructed), axis=1)

            for i, error in enumerate(errors):
                if error <= self.ae_threshold:
                    results[i]["confidence"] = float(1.0 - (error / self.ae_threshold if self.ae_threshold > 0 else 0))

            anomalous_indices = np.where(errors > self.ae_threshold)[0]
            if anomalous_indices.size == 0:
                return results

        except Exception as e:
            print(f"❌ Error during Stage 1 (Autoencoder) anomaly detection: {e}")
            return [{"label": "ANALYSIS_ERROR", "confidence": 1.0}] * num_flows

        # --- Stage 2: DDoS Classification with LightGBM ---
        try:
            df_anomalous = df_full.iloc[anomalous_indices]
            
            # The incoming DataFrame from the controller now has all the correct names
            X_lgbm = df_anomalous[self.ddos_features].astype(np.float64)

            prediction_probs = self.ddos_model.predict_proba(X_lgbm)

            for i, idx in enumerate(anomalous_indices):
                ddos_prob = prediction_probs[i][1]
                if ddos_prob > 0.8:
                    results[idx] = {"label": "DDOS", "confidence": float(ddos_prob)}
                else:
                    results[idx] = {"label": "CONGESTION", "confidence": 1.0 - float(ddos_prob)}
            
            return results

        except Exception as e:
            print(f"❌ Error during Stage 2 (LightGBM) DDoS classification: {e}")
            for idx in anomalous_indices:
                results[idx] = {"label": "ANALYSIS_ERROR", "confidence": 1.0}
            return results