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

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    print(f"Listening on {PORT}...")

    conn, addr = server.accept()
    print("Connected by:", addr)

    recv_thread = threading.Thread(target=receive_messages, args=(conn,), daemon=True)
    recv_thread.start()

    send_messages(conn)

    conn.close()
    server.close()

if __name__ == "__main__":
    main()