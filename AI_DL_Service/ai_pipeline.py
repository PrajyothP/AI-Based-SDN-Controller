# AI-DL_Service/ai_pipeline.py

"""
This module defines the core machine learning pipeline for network threat detection.
It uses a two-stage approach:
1. An Autoencoder model for general anomaly detection to filter normal traffic.
2. A LightGBM classifier to specifically identify DDoS attacks within the anomalous traffic.
Flows that are anomalous but not classified as DDoS are labeled as Congestion.
"""

import keras
import joblib
import pickle
import numpy as np
import os
import pandas as pd

# Define the exact feature order required by the pre-trained Autoencoder model.
AE_FEATURES_ORDER = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Packet Length Mean"
]

# Define the exact feature order required by the pre-trained LightGBM DDoS classifier.
DDoS_FEATURES_ORDER = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Flow Packets/s"
]

def encode_port(port):
    """Categorically encodes destination ports into a smaller set of integers."""
    if port in {80, 443}: return 1 # Common Web
    if port == 53: return 2 # DNS
    if 0 <= port <= 1023: return 3 # Well-known ports
    if 1024 <= port <= 49151: return 4 # Registered ports
    return 5 # Dynamic/Private ports

class AIPipeline:
    """
    Encapsulates the loading of models and the multi-stage analysis process.
    """
    def __init__(self, model_dir='models/'):
        """
        Loads all necessary ML model components from disk upon instantiation.
        
        Args:
            model_dir (str): The directory path where model files are stored.
            
        Raises:
            Exception: If any of the required model files cannot be loaded.
        """
        try:
            # Stage 1: Load Autoencoder components for anomaly detection.
            self.autoencoder = keras.models.load_model(os.path.join(model_dir, 'autoencoder_model.keras'))
            with open(os.path.join(model_dir, 'unified_threshold.pkl'), 'rb') as f:
                self.ae_threshold = pickle.load(f)
            self.ae_scaler = joblib.load(os.path.join(model_dir, 'unified_ae_scaler.pkl'))

            # Stage 2: Load LightGBM components for DDoS classification.
            self.ddos_model = joblib.load(os.path.join(model_dir, 'ddos_model.joblib'))
            with open(os.path.join(model_dir, 'ddos_features.pkl'), 'rb') as f:
                self.ddos_features = pickle.load(f)
            
            print("AI Pipeline initialized successfully. Loaded Autoencoder for anomaly detection and LightGBM for DDoS classification.")
        except Exception as e:
            print(f"FATAL ERROR: Could not load AI models from disk. The pipeline cannot be initialized. Error: {e}")
            raise

    def analyze_flow_batch(self, flow_batch: list):
        """
        Processes a batch of network flows through the two-stage ML pipeline.

        Args:
            flow_batch (list): A list of dictionaries, where each dictionary represents a network flow.

        Returns:
            list: A list of result dictionaries with 'label' and 'confidence' for each flow.
        """
        if not flow_batch: return []
        num_flows = len(flow_batch)
        results = [{"label": "NORMAL", "confidence": 0.0} for _ in range(num_flows)]
        df_full = pd.DataFrame(flow_batch)

        # --- Stage 1: Anomaly Detection with Autoencoder ---
        try:
            df_ae = df_full[AE_FEATURES_ORDER].copy()
            df_ae['Destination Port'] = df_ae['Destination Port'].apply(encode_port)
            
            # Apply log transformation to features with wide dynamic ranges.
            log_features = AE_FEATURES_ORDER[1:]
            for col in log_features:
                df_ae[col] = np.log1p(df_ae[col].clip(lower=0))

            ae_batch_scaled = self.ae_scaler.transform(df_ae)
            reconstructed = self.autoencoder.predict(ae_batch_scaled, verbose=0)
            errors = np.mean(np.square(ae_batch_scaled - reconstructed), axis=1)

            # Initially classify flows based on reconstruction error.
            for i, error in enumerate(errors):
                if error <= self.ae_threshold:
                    results[i]["confidence"] = float(1.0 - (error / self.ae_threshold if self.ae_threshold > 0 else 0))

            # Identify indices of anomalous flows for further analysis.
            anomalous_indices = np.where(errors > self.ae_threshold)[0]
            if anomalous_indices.size == 0:
                return results

        except Exception as e:
            print(f"Error during Stage 1 (Autoencoder) analysis: {e}. This batch will be marked as an analysis error.")
            return [{"label": "ANALYSIS_ERROR", "confidence": 1.0}] * num_flows

        # --- Stage 2: DDoS Classification with LightGBM on Anomalous Flows ---
        try:
            df_anomalous = df_full.iloc[anomalous_indices]
            X_lgbm = df_anomalous[self.ddos_features].astype(np.float64)
            prediction_probs = self.ddos_model.predict_proba(X_lgbm)

            # Classify anomalous flows as either DDoS or Congestion.
            for i, idx in enumerate(anomalous_indices):
                ddos_prob = prediction_probs[i][1] # Probability of the positive (DDoS) class.
                if ddos_prob > 0.8:
                    results[idx] = {"label": "DDOS", "confidence": float(ddos_prob)}
                else:
                    results[idx] = {"label": "CONGESTION", "confidence": 1.0 - float(ddos_prob)}
            
            return results

        except Exception as e:
            print(f"Error during Stage 2 (LightGBM) classification for anomalous flows: {e}. Anomalous flows will be marked as an analysis error.")
            for idx in anomalous_indices:
                results[idx] = {"label": "ANALYSIS_ERROR", "confidence": 1.0}
            return results