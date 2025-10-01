#!/bin/bash

echo "--- Starting Congestion Test (Standard Mode) ---"
TEST_DURATION=60 # seconds
LOG_FILE="congestion_ping_log.txt"

# Clean up any previous Mininet runs
sudo mn -c

# Run the entire test within a single Mininet instance
# Commands are passed directly to the hosts after the Mininet setup arguments.
echo "Launching Mininet and starting iperf/ping processes..."
sudo mn --custom ./mininet/topology.py --controller remote \
    server iperf -s & \
    h2 ping 10.0.2.1 > $LOG_FILE & \
    h1 iperf -c 10.0.2.1 -t $TEST_DURATION -b 10M > /dev/null & \
    h1 iperf -c 10.0.2.1 -t $TEST_DURATION -b 10M > /dev/null & \

MININET_PID=$!

echo "--- Test is running for $TEST_DURATION seconds. ---"
echo "Monitor the OS-ken controller logs for 'CONGESTION' detection."
echo "After the test, check '$LOG_FILE' for latency results."

# Wait for the test to complete
sleep $TEST_DURATION

echo "--- Test finished. Cleaning up. ---"
# Stop the Mininet instance, which also stops all host processes
sudo kill $MININET_PID
# Final cleanup
sudo mn -c

echo "Cleanup complete."