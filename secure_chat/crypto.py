"""End-to-end encrypted, mutually authenticated channel over any reliable byte stream.

Design (small on purpose, uses only well-reviewed primitives from `cryptography`):
  * identity     : each peer has a long-term Ed25519 key (its "fingerprint" is SHA-256 of the public key)
  * key exchange : ephemeral X25519 on every connection  ->  forward secrecy (old sessions stay secret
                   even if an identity key later leaks)
  * authenticate : each side signs the full handshake transcript with its identity key, which binds the
                   ephemeral keys to the identity and defeats a man-in-the-middle
  * trust        : trust-on-first-use pinning (like SSH known_hosts) or an explicit expected fingerprint
  * encryption   : ChaCha20-Poly1305 (AEAD); one key per direction; nonce = 64-bit message counter,
                   so a replayed, dropped, reordered or modified frame fails to decrypt
  * framing      : 4-byte big-endian length, then ciphertext
NOT provided: metadata protection (peers' IPs, message sizes/timing are visible), deniability, group chat,
post-compromise security (no ratchet), padding.
"""
import hashlib
import json
import os
import struct

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_FRAME = 1 << 20
PROTOCOL = b"p2p-secure-chat-v1"
_RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


class HandshakeError(Exception):
    pass


class UnknownPeer(HandshakeError):
    pass


def fingerprint(pub_raw: bytes) -> str:
    h = hashlib.sha256(pub_raw).hexdigest()
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))          # 128 bits, grouped for reading aloud


class Identity:
    """Long-term Ed25519 identity, stored on disk with owner-only permissions."""

    def __init__(self, key: Ed25519PrivateKey):
        self.key = key
        self.public = key.public_key().public_bytes(**_RAW)
        self.fingerprint = fingerprint(self.public)

    @classmethod
    def load_or_create(cls, path):
        if os.path.exists(path):
            with open(path, "rb") as f:
                return cls(Ed25519PrivateKey.from_private_bytes(f.read()))
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
                                encryption_algorithm=serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        return cls(key)


class KnownPeers:
    """Trust-on-first-use pin store: name -> fingerprint. A changed fingerprint is a hard error."""

    def __init__(self, path):
        self.path = path
        self.pins = {}
        if os.path.exists(path):
            with open(path) as f:
                self.pins = json.load(f)

    def check(self, name, fp, accept_new=True):
        if name in self.pins:
            if self.pins[name] != fp:
                raise HandshakeError(f"identity of '{name}' CHANGED (pinned {self.pins[name]}, got {fp}): possible man-in-the-middle")
            return "pinned"
        if not accept_new:
            raise UnknownPeer(f"unknown peer '{name}' with fingerprint {fp}")
        self.pins[name] = fp
        with open(self.path, "w") as f:
            json.dump(self.pins, f, indent=2)
        return "new"


def _send_frame(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise ConnectionError("peer closed the connection")
        buf += part
    return bytes(buf)


def _recv_frame(sock):
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > MAX_FRAME:
        raise HandshakeError("frame too large")
    return _recv_exact(sock, n)


class SecureChannel:
    def __init__(self, sock, send_key, recv_key, peer_fingerprint, peer_public):
        self.sock = sock
        self._send, self._recv = ChaCha20Poly1305(send_key), ChaCha20Poly1305(recv_key)
        self._send_ctr = self._recv_ctr = 0
        self.peer_fingerprint, self.peer_public = peer_fingerprint, peer_public

    @staticmethod
    def _nonce(ctr):
        return b"\0\0\0\0" + struct.pack(">Q", ctr)

    def send(self, plaintext: bytes):
        ct = self._send.encrypt(self._nonce(self._send_ctr), plaintext, None)
        self._send_ctr += 1
        _send_frame(self.sock, ct)

    def recv(self) -> bytes:
        ct = _recv_frame(self.sock)
        try:
            pt = self._recv.decrypt(self._nonce(self._recv_ctr), ct, None)
        except InvalidTag:
            raise HandshakeError("message failed authentication (tampered, replayed or reordered)")
        self._recv_ctr += 1
        return pt

    def close(self):
        try: self.sock.close()
        except OSError: pass


def handshake(sock, identity: Identity, initiator: bool, peers: KnownPeers, peer_name: str,
              expected_fingerprint: str = None, accept_new: bool = True) -> SecureChannel:
    """Mutually authenticated key exchange. `initiator` is the side that opened the TCP connection."""
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(**_RAW)
    mine = eph_pub + identity.public
    _send_frame(sock, mine)
    theirs = _recv_frame(sock)
    if len(theirs) != 64:
        raise HandshakeError("malformed hello")
    peer_eph, peer_id = theirs[:32], theirs[32:]

    # transcript is ordered initiator-first so both sides sign/verify the same bytes
    transcript = PROTOCOL + (mine + theirs if initiator else theirs + mine)
    role_tag = b"I" if initiator else b"R"
    _send_frame(sock, identity.key.sign(role_tag + transcript))
    sig = _recv_frame(sock)
    try:
        Ed25519PublicKey.from_public_bytes(peer_id).verify(sig, (b"R" if initiator else b"I") + transcript)
    except InvalidSignature:
        raise HandshakeError("peer failed to prove its identity (bad signature)")

    fp = fingerprint(peer_id)
    if expected_fingerprint is not None and fp != expected_fingerprint:
        raise HandshakeError(f"fingerprint mismatch: expected {expected_fingerprint}, got {fp}")
    peers.check(peer_name, fp, accept_new)

    shared = eph.exchange(X25519PublicKey.from_public_bytes(peer_eph))
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=hashlib.sha256(transcript).digest(), info=PROTOCOL).derive(shared)
    k_i2r, k_r2i = okm[:32], okm[32:]
    send_key, recv_key = (k_i2r, k_r2i) if initiator else (k_r2i, k_i2r)
    return SecureChannel(sock, send_key, recv_key, fp, peer_id)
