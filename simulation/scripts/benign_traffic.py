#!/usr/bin/env python3
"""
benign_traffic.py - Generate normal IoT traffic
Each IoT device sends realistic sensor-like packets to the cloud server.

How to run inside Mininet:
    xterm iot1 iot2 iot3 iot4 iot5 iot6 iot7 iot8 iot9 iot10
    On each xterm window:
        python3 /home/vynox/fyp/simulation/scripts/benign_traffic.py
"""

import random
import time
import socket
import sys

# Cloud server IP from your topology
SERVER_IP = "10.0.0.1"

# Different "services" benign traffic might use
SERVICE_PORTS = [80, 443, 1883, 8883, 5683]  # HTTP, HTTPS, MQTT, MQTT-TLS, CoAP

# How long to run (in seconds) - default 60 minutes
DURATION_SECONDS = 3600


def send_sensor_data(server_ip, port, message):
    """Send one sensor reading to the server using TCP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((server_ip, port))
        sock.send(message.encode())
        sock.close()
    except Exception:
        pass  # Server might not be listening on that port, that's OK


def generate_benign_traffic():
    """Continuously send realistic IoT-like traffic."""
    print(f"[benign] Starting benign traffic to {SERVER_IP} for {DURATION_SECONDS}s")

    start_time = time.time()
    packet_count = 0

    while time.time() - start_time < DURATION_SECONDS:
        # Pick a random service port
        port = random.choice(SERVICE_PORTS)

        # Create realistic IoT-like message
        sensor_value = round(random.uniform(15.0, 35.0), 2)  # Temperature
        humidity = random.randint(30, 80)
        message = f"SENSOR_DATA temp={sensor_value} humidity={humidity}"

        send_sensor_data(SERVER_IP, port, message)
        packet_count += 1

        # Sleep 0.1-1 second between packets (100-500 pkts/sec range)
        sleep_time = random.uniform(0.002, 0.01)
        time.sleep(sleep_time)

        # Print progress every 1000 packets
        if packet_count % 1000 == 0:
            elapsed = int(time.time() - start_time)
            print(f"[benign] {packet_count} packets sent in {elapsed}s")

    print(f"[benign] DONE. Total packets sent: {packet_count}")


if __name__ == "__main__":
    generate_benign_traffic()
