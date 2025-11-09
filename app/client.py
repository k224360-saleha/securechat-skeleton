"""Client skeleton — plain TCP; no TLS. See assignment spec."""

# def main():
#     raise NotImplementedError("students: implement client workflow")

# if __name__ == "__main__":
#     main()

import socket, json

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 5000))

# Step 1: Send hello
hello = {"type": "hello", "msg": "Hi server!"}
client.send(json.dumps(hello).encode())

# Step 2: Receive hello response
resp = json.loads(client.recv(1024).decode())
print("Server:", resp)

# Step 3: Send login (unencrypted)
login = {"type": "login", "username": "saleha", "password": "1234"}
client.send(json.dumps(login).encode())

# Step 4: Receive login response
resp = json.loads(client.recv(1024).decode())
print("Server:", resp)

client.close()
