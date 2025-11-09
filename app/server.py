"""Server skeleton — plain TCP; no TLS. See assignment spec."""

# def main():
#     raise NotImplementedError("students: implement server workflow")

# if __name__ == "__main__":
#     main()

import socket, json

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 5000))
server.listen(1)
print("Server ready...")

conn, addr = server.accept()
print(f"Connected by {addr}")

# Step 1: Receive hello
data = json.loads(conn.recv(1024).decode())
if data["type"] == "hello":
    print("Client said hello!")
    conn.send(json.dumps({"type": "server_hello", "msg": "Hello client!"}).encode())

# Step 2: Receive login
data = json.loads(conn.recv(1024).decode())
if data["type"] == "login":
    username = data["username"]
    password = data["password"]
    print(f"Login attempt: {username}, {password}")

    # Dummy check
    if username == "saleha" and password == "1234":
        response = {"type": "login_response", "status": "success"}
    else:
        response = {"type": "login_response", "status": "fail"}

    conn.send(json.dumps(response).encode())

conn.close()

