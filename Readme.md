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
```
Listening on 3939...
```

**On the client machine:**
```bash
python client.py
```
You should see:
```
Connected!
```

Once connected, both sides can type and send messages at any time —
incoming messages will print automatically without interrupting what
you're typing.

## How it works

- `server.py` opens a TCP socket, binds it to a port, and waits for a
  connection
- `client.py` connects directly to the server's IP and port
- Once connected, each side spins up a background thread dedicated to
  *receiving* messages, while the main thread stays free to *send*
  messages via `input()`
- This threading is what allows simultaneous send/receive instead of
  strict turn-based messaging

## Limitations / Next steps

This is a learning project, not production-ready software. Known gaps:

- No encryption — messages are sent in plaintext
- Only supports one client at a time
- No NAT traversal — works on the same LAN, or requires manual port
  forwarding for internet use
- No peer discovery — you must manually know and enter the IP address
- No offline message delivery — if either side disconnects, messages
  are lost

Possible improvements:
- Add TLS or a simple encryption layer (e.g. `cryptography` library) for
  message confidentiality
- Support multiple clients via a broadcast or relay model
- Add message history / local persistence with SQLite
- Explore `libp2p` or `WebRTC` for real peer discovery and NAT traversal

## License

MIT