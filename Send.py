import socket
import threading

SERVER_IP = "192.168.1.42"  # <-- replace with the server machine's actual LAN IP
PORT = 3939

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("\nServer disconnected.")
                break
            print(f"\nFriend: {data.decode()}\nYou: ", end="", flush=True)
        except (ConnectionResetError, OSError):
            print("\nConnection closed.")
            break

def send_messages(sock):
    while True:
        try:
            message = input("You: ")
            sock.sendall(message.encode())
        except (EOFError, OSError):
            break

