#!/usr/bin/env python3
"""
server_listener.py - Cloud server that accepts IoT connections
Run this on the 'server' host inside Mininet.
"""

import socket
import threading

PORTS = [80, 443, 1883, 8883, 5683]


def listen_on_port(port):
    """Listen for connections on one port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(50)
    print(f"[server] Listening on port {port}")

    while True:
        try:
            conn, addr = sock.accept()
            data = conn.recv(1024)
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    # Start a listener thread for each port
    for port in PORTS:
        t = threading.Thread(target=listen_on_port, args=(port,), daemon=True)
        t.start()

    print("[server] Server is running. Press Ctrl+C to stop.")
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[server] Stopped.")
