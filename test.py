# test_pipeline.py

from osken_app.ai_pipeline import AIPipeline

# This script verifies that all models and scalers load correctly
# and that the prediction pipeline can be executed.

def run_tests():
    print("--- Initializing AI Pipeline ---")
    pipeline = AIPipeline(model_dir='models/')

    # --- Test Case 1: Sample Normal Traffic ---
    print("\n--- Testing with sample NORMAL traffic ---")
    normal_traffic = {
        # AE Features
        "Destination Port": 80,
        "Flow Duration": 50000,
        "Total Fwd Packets": 5,
        "Total Backward Packets": 3,
        "Total Length of Fwd Packets": 100,
        "Total Length of Bwd Packets": 150,
        "Packet Length Mean": 40.0,
        # DDoS Features (some overlap)
        " Flow Duration": 50000,
        " Total Fwd Packets": 5,
        " Total Backward Packets": 3,
        "Total Length of Fwd Packets": 100,
        " Total Length of Bwd Packets": 150,
        " Fwd Packet Length Mean": 20.0,
        " Bwd Packet Length Mean": 50.0,
        " Flow Packets/s": 160
    }
    result = pipeline.analyze_traffic_flow(normal_traffic)
    print(f"Result: {result}")
    assert result == "NORMAL", "Test failed for normal traffic!"
    print("✅ Normal traffic test passed.")

    # --- Test Case 2: Sample DDoS Traffic ---
    print("\n--- Testing with sample DDOS traffic ---")
    ddos_traffic = {
        "Destination Port": 80,
    " Flow Duration": 2.0,                      # seconds (short, high-rate flow)
    " Total Fwd Packets": 50000,                # attacker → victim
    " Total Backward Packets": 50,              # very few responses from victim
    "Total Length of Fwd Packets": 3_000_000,   # bytes (50000 * 60 B avg)
    " Total Length of Bwd Packets": 3_000,      # bytes (50 * 60 B avg)
    " Fwd Packet Length Mean": 60.0,            # bytes
    " Bwd Packet Length Mean": 60.0,            # bytes
    " Flow Packets/s": 25025.0                  # (50000 + 50) / 2.0
    }
    result = pipeline.analyze_traffic_flow(ddos_traffic)
    print(f"Result: {result}")
    assert result == "DDOS", "Test failed for DDoS traffic!"
    print("✅ DDoS traffic test passed.")

if __name__ == "__main__":
    run_tests()