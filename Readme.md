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

## Files

- `server.py` — run this on the machine that will "host" the chat
- `client.py` — run this on the machine that will "connect" to the host

## Setup

1. On the **server** machine, find its local IP address:
   - Windows: `ipconfig` (look for IPv4 Address, e.g. `192.168.1.42`)
   - macOS/Linux: `ifconfig` or `ip addr`

2. Open `client.py` and set `SERVER_IP` to that address:
```python
   SERVER_IP = "192.168.1.42"
```

3. Make sure port `3939` isn't blocked by a firewall on the server machine.

## Running

**On the server machine:**
```bash
python server.py
```
You should see: