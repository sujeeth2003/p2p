import socket
import threading

HOST = "0.0.0.0"
PORT = 3939

def receive_messages(conn):
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                print("\nFriend disconnected.")
                break
            print(f"\nFriend: {data.decode()}\nYou: ", end="", flush=True)
        except (ConnectionResetError, OSError):
            print("\nConnection closed.")
            break

def send_messages(conn):
    while True:
        try:
            message = input("You: ")
            conn.sendall(message.encode())
        except (EOFError, OSError):
            break

