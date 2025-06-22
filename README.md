# Peer-to-Peer Encrypted Messenger

Two computers chat directly, with **no server in the middle and no third party**, and the messages are end-to-end encrypted and authenticated. Python + the `cryptography` library.

The repo has two stages:

| | What it is |
|---|---|
| [`plain_sockets_v1/`](plain_sockets_v1) | The first version: raw TCP sockets + threads, no encryption. Good for understanding how a two-way socket chat works |
| [`secure_chat/`](secure_chat) | The real thing: authenticated key exchange and AEAD-encrypted messages on top of the same idea |

## Security design (`secure_chat/crypto.py`)
- **Identity:** each user has a long-term Ed25519 key (`identity.key`, created with `0600` permissions); the fingerprint is the SHA-256 of the public key.
- **Key exchange:** a fresh ephemeral **X25519** exchange on every connection gives **forward secrecy**.
- **Authentication:** both sides sign the whole handshake transcript with their identity key. A man-in-the-middle cannot substitute keys without failing verification.
- **Trust:** read your fingerprint to your peer over a trusted channel and pass theirs with `--expect`, or rely on **trust-on-first-use** pinning (like SSH `known_hosts`). If a pinned peer's identity ever changes the connection is refused.
- **Encryption:** **ChaCha20-Poly1305**, separate keys per direction (HKDF-SHA256), nonce = message counter, so tampered, replayed, dropped or reordered messages fail authentication.

### What it does not do
Hide metadata (IP addresses, timing, message sizes), rotate keys within a session (no double ratchet), support groups or offline delivery, or work through NAT without port forwarding. It has **not been independently audited**. Use Signal for anything that matters.

## Run
```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v        # 9 tests

# machine A                                       # machine B
python -m secure_chat.chat listen 5000            python -m secure_chat.chat connect <A's IP> 5000
```
Each side prints its fingerprint on start-up. Compare them out of band, then pin with `--expect <fingerprint>` on later runs.

## Tests
Round trip in both directions (100 messages), plaintext absent from the bytes on the wire, tampered frame rejected, replayed frame rejected, fresh session keys per connection, wrong expected fingerprint refused, TOFU key-change detection, a simulated man-in-the-middle that substitutes its own identity, identity persistence.
