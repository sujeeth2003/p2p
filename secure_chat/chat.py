"""Command-line encrypted chat between two machines, no server in the middle.

    python -m secure_chat.chat listen 5000                    # on machine A
    python -m secure_chat.chat connect 192.168.1.42 5000      # on machine B

First run creates identity.key (keep it private) and prints your fingerprint. Read the fingerprint to your
peer over a channel you trust (phone call, in person) and pass theirs with --expect to be certain nobody sits
in the middle. Without --expect the first connection is pinned (trust-on-first-use) and any later change is refused.
"""
import argparse
import os
import socket
import sys
import threading

from .crypto import HandshakeError, Identity, KnownPeers, handshake


def run_chat(ch):
    def reader():
        try:
            while True:
                print(f"\r< {ch.recv().decode(errors='replace')}\n> ", end="", flush=True)
        except (ConnectionError, HandshakeError, OSError) as e:
            print(f"\n[connection ended: {e}]")
            os._exit(0)
    threading.Thread(target=reader, daemon=True).start()
    try:
        for line in sys.stdin:
            ch.send(line.rstrip("\n").encode())
            print("> ", end="", flush=True)
    except (KeyboardInterrupt, OSError):
        pass
    ch.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["listen", "connect"])
    ap.add_argument("args", nargs="+", help="listen: PORT   connect: HOST PORT")
    ap.add_argument("--name", default="peer", help="label for the pinned peer identity")
    ap.add_argument("--expect", help="peer's fingerprint (verified out of band); refuse anything else")
    ap.add_argument("--identity", default="identity.key")
    ap.add_argument("--peers", default="known_peers.json")
    a = ap.parse_args()

    me = Identity.load_or_create(a.identity)
    print(f"your fingerprint: {me.fingerprint}")
    peers = KnownPeers(a.peers)
    if a.mode == "listen":
        srv = socket.create_server(("0.0.0.0", int(a.args[0])))
        print(f"waiting on port {a.args[0]} ...")
        sock, addr = srv.accept()
        initiator = False
    else:
        sock = socket.create_connection((a.args[0], int(a.args[1])))
        initiator = True
    try:
        ch = handshake(sock, me, initiator, peers, a.name, a.expect)
    except HandshakeError as e:
        print(f"REFUSED: {e}")
        return 1
    print(f"secure channel up. peer fingerprint: {ch.peer_fingerprint}  ({'expected' if a.expect else 'pinned/TOFU'})")
    run_chat(ch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
