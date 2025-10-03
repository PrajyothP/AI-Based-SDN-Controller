import keras
import joblib
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
    " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
    "Total Length of Fwd Packets", " Total Length of Bwd Packets",
    " Fwd Packet Length Mean", " Bwd Packet Length Mean", " Flow Packets/s"
]

class AIPipeline:
    def __init__(self, model_dir='models/'):
        """Initializes the AI pipeline by loading all models and scalers."""
        try:
            # --- Load Autoencoder Components ---
            self.autoencoder = keras.models.load_model(os.path.join(model_dir, 'autoencoder_model.keras'))
            
            ae_scaler_path = os.path.join(model_dir, 'scalers/autoencoder/')
            # Use pickle to load the threshold file
            with open(os.path.join(ae_scaler_path, 'threshold.pkl'), 'rb') as f:
                self.ae_threshold = pickle.load(f)


            # Load the 6 individual scalers for the autoencoder into a dictionary
            self.ae_scalers = {
                # These scalers were likely saved with pickle or joblib.
                # Use the library they were saved with. Assuming joblib for consistency.
                "Flow Duration": joblib.load(os.path.join(ae_scaler_path, 'flow_duration_scaler.pkl')),
                "Total Fwd Packets": joblib.load(os.path.join(ae_scaler_path, 'total_fwd_packets_scaler.pkl')),
                "Total Backward Packets": joblib.load(os.path.join(ae_scaler_path, 'total_bwd_packets_scaler.pkl')),
                "Total Length of Fwd Packets": joblib.load(os.path.join(ae_scaler_path, 'total_len_fwd_packets_scaler.pkl')),
                "Total Length of Bwd Packets": joblib.load(os.path.join(ae_scaler_path, 'total_len_bwd_packets_scaler.pkl')),
                "Packet Length Mean": joblib.load(os.path.join(ae_scaler_path, 'packet_len_mean_scaler.pkl')),
            }

            # --- Load DDoS Classifier Components ---
            ddos_scaler_path = os.path.join(model_dir, 'scalers/ddos/')
            self.ddos_model = keras.models.load_model(os.path.join(model_dir, 'ddos_model.keras'))
            self.forest_embedder = joblib.load(os.path.join(model_dir, 'forest_embedder.joblib'))
            self.ddos_scaler = joblib.load(os.path.join(ddos_scaler_path, 'ddos_scaler.joblib'))
            # Use pickle to load the max value file
            with open(os.path.join(ddos_scaler_path, 'forest_emb_max.pkl'), 'rb') as f:
                self.forest_emb_max = pickle.load(f)
            
            print("✅ AI Pipeline initialized successfully with all components.")
        except FileNotFoundError as e:
            print(f"FATAL ERROR: A required model file was not found: {e}")
            print("Please ensure all .keras, .pkl, and .joblib files are in the correct directories.")
            raise
        except Exception as e:
            print(f"FATAL ERROR loading AI models: {e}")
            raise

    def analyze_traffic_flow(self, feature_dict):
        # ... (The rest of this method is correct) ...
        # --- Stage 1: Anomaly Detection with Autoencoder ---
        try:
            ae_input = []
            for feature_name in AE_FEATURES_ORDER:
                raw_value = np.array([[feature_dict[feature_name]]])
                if feature_name in self.ae_scalers:
                    scaled_value = self.ae_scalers[feature_name].transform(raw_value)[0][0]
                    ae_input.append(scaled_value)
                else:
                    ae_input.append(raw_value[0][0])
            ae_input = np.array(ae_input, dtype=np.float32).reshape(1, -1)
            reconstructed = self.autoencoder.predict(ae_input, verbose=0)
            error = np.mean(np.square(ae_input - reconstructed))
            if error < self.ae_threshold:
                return "NORMAL"
            print(f"Anomaly detected! Error: {error:.6f} > Threshold: {self.ae_threshold:.6f}")
        except Exception as e:
            print(f"Error during anomaly detection: {e}")
            return "ANALYSIS_ERROR"

        # --- Stage 2: DDoS Classification ---
        try:
            df_input = pd.DataFrame([feature_dict])
            X_input = df_input[DDoS_FEATURES_ORDER].replace([np.inf, -np.inf], 0.0).fillna(0.0)
            X_scaled = self.ddos_scaler.transform(X_input)
            X_emb = self.forest_embedder.apply(X_scaled).astype(np.float32)
            X_emb /= self.forest_emb_max
            prediction_prob = self.ddos_model.predict(X_emb, verbose=0)[0][0]
            print(prediction_prob)
            if prediction_prob > 0.3:
                print(f"Attack classified as DDoS with probability: {prediction_prob:.2f}")
                return "DDOS"
            else:
                print(f"🚦 Attack classified as Congestion.")
                return "CONGESTION"
        except Exception as e:
            print(f"Error during DDoS classification: {e}")
            return "ANALYSIS_ERROR"
        
    def analyze_flow_batch(self, flow_batch: list):
        """
        Analyzes a batch of flows and returns a list of classifications.

        :param flow_batch: A list of feature dictionaries.
        :return: A list of strings: "NORMAL", "CONGESTION", or "DDOS".
        """
        if not flow_batch:
            return []

        num_flows = len(flow_batch)
        results = ["NORMAL"] * num_flows # Default classification

        # --- Stage 1: Anomaly Detection with Autoencoder (in Batch) ---
        try:
            ae_batch = []
            for feature_dict in flow_batch:
                ae_input_row = []
                for feature_name in AE_FEATURES_ORDER:
                    raw_value = np.array([[feature_dict[feature_name]]])
                    if feature_name in self.ae_scalers:
                        scaled_value = self.ae_scalers[feature_name].transform(raw_value)[0][0]
                        ae_input_row.append(scaled_value)
                    else:
                        ae_input_row.append(raw_value[0][0])
                ae_batch.append(ae_input_row)

            ae_batch = np.array(ae_batch, dtype=np.float32)
            
            reconstructed_batch = self.autoencoder.predict(ae_batch, verbose=0)
            errors = np.mean(np.square(ae_batch - reconstructed_batch), axis=1)

            # Identify indices of anomalous flows
            anomalous_indices = np.where(errors > self.ae_threshold)[0]
            if anomalous_indices.size == 0:
                return results # All flows are normal

            print(f"⚠️  {len(anomalous_indices)} anomalous flows detected for Stage 2 analysis.")
        
        except Exception as e:
            print(f"❌ Error during batch anomaly detection: {e}")
            return ["ANALYSIS_ERROR"] * num_flows

        # --- Stage 2: DDoS Classification (on anomalous flows only) ---
        try:
            # Create a sub-batch with only the anomalous flows
            ddos_sub_batch = [flow_batch[i] for i in anomalous_indices]
            
            df_input = pd.DataFrame(ddos_sub_batch)
            X_input = df_input[DDoS_FEATURES_ORDER].replace([np.inf, -np.inf], 0.0).fillna(0.0)

            X_scaled = self.ddos_scaler.transform(X_input)
            X_emb = self.forest_embedder.apply(X_scaled).astype(np.float32)
            X_emb /= self.forest_emb_max
            
            # Get predictions for all anomalous flows in one call
            prediction_probs = self.ddos_model.predict(X_emb, verbose=0)

            # Update results for the anomalous flows
            for i, idx in enumerate(anomalous_indices):
                if prediction_probs[i][0] > 0.5:
                    results[idx] = "DDOS"
                else:
                    results[idx] = "CONGESTION"
            
            return results

        except Exception as e:
            print(f"❌ Error during batch DDoS classification: {e}")
            # Mark all anomalies as ANALYSIS_ERROR if this stage fails
            for idx in anomalous_indices:
                results[idx] = "ANALYSIS_ERROR"
            return results