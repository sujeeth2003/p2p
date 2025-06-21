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


