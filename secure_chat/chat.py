"""Command-line encrypted chat between two machines, no server in the middle.

    python -m secure_chat.chat listen 5000                    # on machine A
    python -m secure_chat.chat connect 192.168.1.42 5000      # on machine B

First run creates identity.key (keep it private) and prints your fingerprint. Read the fingerprint to your
peer over a channel you trust (phone call, in person) and pass theirs with --expect to be certain nobody sits
in the middle. Without --expect the first connection is pinned (trust-on-first-use) and any later change is refused.
"""
import argparse
import os
import socket
import sys
import threading

from .crypto import HandshakeError, Identity, KnownPeers, handshake


def run_chat(ch):
    def reader():
        try:
            while True:
                print(f"\r< {ch.recv().decode(errors='replace')}\n> ", end="", flush=True)
        except (ConnectionError, HandshakeError, OSError) as e:
            print(f"\n[connection ended: {e}]")
            os._exit(0)
    threading.Thread(target=reader, daemon=True).start()
    try:
        for line in sys.stdin:
            ch.send(line.rstrip("\n").encode())
            print("> ", end="", flush=True)
    except (KeyboardInterrupt, OSError):
        pass
    ch.close()

