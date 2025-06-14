# Simple P2P Chat (Python Sockets)

A minimal two-way chat app using raw TCP sockets and threading — no external
libraries required. One machine runs as the "server" (listener), the other
connects as the "client." Once connected, both sides can send and receive
messages independently, without waiting for the other to speak first.

> Note: this is a direct socket connection between two machines on the same
> network (or via port forwarding for the internet) — not a fully
> decentralized P2P network with peer discovery. It's a good first step
> toward understanding how P2P messaging works at the socket level.

## Requirements

- Python 3.7+
- Both machines on the same network (Wi-Fi/LAN), OR port forwarding set up
  if connecting over the internet

