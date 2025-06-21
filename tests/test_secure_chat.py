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


def run_handshakes(alice, bob, **kw):
    """Handshake both sides concurrently; returns (channel_a, channel_b) or raises the first error."""
    sa, sb = connected_pair()
    out, errs = {}, {}

    def side(tag, sock, ident, peers, init, name, extra):
        try:
            out[tag] = handshake(sock, ident, init, peers, name, **extra)
        except Exception as e:
            errs[tag] = e
    ta = threading.Thread(target=side, args=("a", sa, alice[0], alice[1], True, "bob", kw.get("a_extra", {})))
    tb = threading.Thread(target=side, args=("b", sb, bob[0], bob[1], False, "alice", kw.get("b_extra", {})))
    ta.start(); tb.start(); ta.join(5); tb.join(5)
    return out, errs, (sa, sb)


class SecureChatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.alice, self.bob = make_peer(self.tmp, "alice"), make_peer(self.tmp, "bob")

    def test_roundtrip_both_directions(self):
        out, errs, _ = run_handshakes(self.alice, self.bob)
        self.assertEqual(errs, {})
        a, b = out["a"], out["b"]
        a.send(b"hello bob"); self.assertEqual(b.recv(), b"hello bob")
        b.send(b"hi alice"); self.assertEqual(a.recv(), b"hi alice")
        for i in range(100):
            a.send(f"m{i}".encode()); self.assertEqual(b.recv(), f"m{i}".encode())
        self.assertEqual(a.peer_fingerprint, self.bob[0].fingerprint)
        self.assertEqual(b.peer_fingerprint, self.alice[0].fingerprint)

