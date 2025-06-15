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

