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

    def test_ciphertext_on_the_wire_hides_plaintext(self):
        out, errs, (sa, sb) = run_handshakes(self.alice, self.bob)
        secret = b"the launch code is 0000-hunter2"
        out["a"].send(secret)
        sb.settimeout(2)
        wire = sb.recv(4096)                       # look at the raw bytes instead of decrypting
        self.assertNotIn(b"hunter2", wire)
        self.assertNotIn(b"launch", wire)

    def test_tampered_frame_is_rejected(self):
        out, _, (sa, sb) = run_handshakes(self.alice, self.bob)
        a, b = out["a"], out["b"]
        ct = a._send.encrypt(a._nonce(a._send_ctr), b"pay $10", None)
        a._send_ctr += 1
        flipped = bytearray(ct); flipped[0] ^= 1
        crypto._send_frame(sa, bytes(flipped))
        with self.assertRaises(HandshakeError): b.recv()

    def test_replayed_frame_is_rejected(self):
        out, _, (sa, sb) = run_handshakes(self.alice, self.bob)
        a, b = out["a"], out["b"]
        ct = a._send.encrypt(a._nonce(a._send_ctr), b"transfer", None)
        a._send_ctr += 1
        crypto._send_frame(sa, ct); self.assertEqual(b.recv(), b"transfer")
        crypto._send_frame(sa, ct)                 # attacker resends the same frame
        with self.assertRaises(HandshakeError): b.recv()

    def test_sessions_use_fresh_keys(self):
        o1, _, _ = run_handshakes(self.alice, self.bob)
        o2, _, _ = run_handshakes(self.alice, self.bob)
        ct1 = o1["a"]._send.encrypt(b"\0" * 12, b"same", None)
        ct2 = o2["a"]._send.encrypt(b"\0" * 12, b"same", None)
        self.assertNotEqual(ct1, ct2)              # forward secrecy: ephemeral keys differ per connection

    def test_wrong_expected_fingerprint_refused(self):
        _, errs, _ = run_handshakes(self.alice, self.bob, a_extra={"expected_fingerprint": "dead:beef"})
        self.assertIn("a", errs); self.assertIsInstance(errs["a"], HandshakeError)

    def test_tofu_pins_and_detects_key_change(self):
        out, errs, _ = run_handshakes(self.alice, self.bob); self.assertEqual(errs, {})
        # bob "reinstalls" and gets a new identity but keeps the name -> alice must refuse
        os.remove(os.path.join(self.tmp, "bob.key"))
        bob2 = make_peer(self.tmp, "bob")
        _, errs, _ = run_handshakes(self.alice, bob2)
        self.assertIn("a", errs)
        self.assertIn("CHANGED", str(errs["a"]))

    def test_man_in_the_middle_cannot_forge_identity(self):
        # Mallory relays bob's hello but substitutes her own signature: the handshake must fail.
        mallory = make_peer(self.tmp, "mallory")
        sa, sm = connected_pair()
        result = {}

        def alice_side():
            try: handshake(sa, self.alice[0], True, self.alice[1], "bob", expected_fingerprint=self.bob[0].fingerprint)
            except HandshakeError as e: result["err"] = e
        t = threading.Thread(target=alice_side); t.start()
        m_hello = crypto._recv_frame(sm)                      # alice's hello
        crypto._send_frame(sm, m_hello[:32] + mallory[0].public)   # mallory answers with HER identity
        crypto._recv_frame(sm)                                # alice's signature
        crypto._send_frame(sm, mallory[0].key.sign(b"whatever"))
        t.join(5)
        self.assertIn("err", result)

    def test_identity_file_not_overwritten_and_persistent(self):
        again = Identity.load_or_create(os.path.join(self.tmp, "alice.key"))
        self.assertEqual(again.fingerprint, self.alice[0].fingerprint)


if __name__ == "__main__":
    unittest.main(verbosity=2)
