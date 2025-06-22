# Peer-to-Peer Encrypted Messenger

Two computers chat directly, with **no server in the middle and no third party**, and the messages are end-to-end encrypted and authenticated. Python + the `cryptography` library.

The repo has two stages:

| | What it is |
|---|---|
| [`plain_sockets_v1/`](plain_sockets_v1) | The first version: raw TCP sockets + threads, no encryption. Good for understanding how a two-way socket chat works |
| [`secure_chat/`](secure_chat) | The real thing: authenticated key exchange and AEAD-encrypted messages on top of the same idea |

