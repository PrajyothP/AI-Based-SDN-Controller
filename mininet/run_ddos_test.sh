#!/bin/bash

echo "--- Starting DDoS Mitigation Test (Standard Mode) ---"
TEST_DURATION=60 # seconds
ATTACK_START_DELAY=10 # seconds
LOG_FILE="legitimate_traffic_log.txt"

# Clean up any previous Mininet runs
sudo mn -c

# Check for hping3 and install if needed
if ! command -v hping3 &> /dev/null; then
    echo "hping3 not found. Please install it with: sudo apt-get update && sudo apt-get install -y hping3"
    exit 1
fi

# Run the entire test within a single Mininet instance
echo "Launching Mininet, starting legitimate traffic..."
sudo mn --custom ./mininet_sim/topology.py --controller remote \
    server iperf -s & \
    h1 iperf -c 10.0.2.1 -t $TEST_DURATION -b 1M -i 2 > $LOG_FILE & \
    attacker1 bash -c "echo 'Attacker waiting for $ATTACK_START_DELAY seconds...'; sleep $ATTACK_START_DELAY; echo '--- LAUNCHING DDoS ATTACK NOW ---'; sudo hping3 -S --flood -p 80 10.0.2.1" &
    
MININET_PID=$!

echo "--- Test is running for $TEST_DURATION seconds. ---"
echo "Monitor the OS-ken controller logs for 'DDOS' detection."
echo "Monitor '$LOG_FILE' to see throughput changes."

# Wait for the test to complete
sleep $TEST_DURATION

echo "--- Test finished. Cleaning up. ---"
sudo kill $MININET_PID
# Final cleanup
sudo mn -c

echo "Cleanup complete."