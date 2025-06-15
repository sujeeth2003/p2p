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


