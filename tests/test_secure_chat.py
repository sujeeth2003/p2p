import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secure_chat import HandshakeError, Identity, KnownPeers, handshake  # noqa: E402
from secure_chat import crypto  # noqa: E402


def make_peer(tmp, name):
    return Identity.load_or_create(os.path.join(tmp, f"{name}.key")), KnownPeers(os.path.join(tmp, f"{name}.pins"))


def connected_pair():
    a, b = socket.socketpair()
    return a, b


