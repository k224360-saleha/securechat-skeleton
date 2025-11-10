"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket, json, base64, hashlib, os
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import DNSName, SubjectAlternativeName
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from datetime import datetime, timezone
from app.common.protocol import (
    ClientHello,
    ServerHello,
    ClientDH,
    ServerDH,
    ClientRegister,
    ClientLogin,
    ServerRegisterResponse,
    ServerLoginResponse,
)

CLIENT_CERT_PATH = "certs/client.crt"
CA_CERT_PATH = "certs/ca.crt"

def show_auth_menu():
    """
    Display a simple menu for registration or login.
    Returns:
        choice (str): 'register' or 'login'
    """
    while True:
        print("\n=== SecureChat Authentication ===")
        print("1. Register")
        print("2. Login")
        print("3. Quit")
        choice = input("Select an option (1-3): ").strip()

        if choice == "1":
            return "register"
        elif choice == "2":
            return "login"
        elif choice == "3":
            print("Exiting...")
            exit(0)
        else:
            print("Invalid choice, please try again.")



def collect_credentials(action):
    email = input("Enter your email: ").strip()
    pwd = input("Enter your password: ").strip()
    if action == "register":
        username = input("Enter your username: ").strip()
        return ClientRegister(type="register", email=email, username=username, pwd=pwd)
    else:
        nonce = base64.b64encode(os.urandom(8)).decode()
        return ClientLogin(type="login", email=email, pwd=pwd, nonce=nonce)

def encrypt_payload(key, data):
    plaintext = data.model_dump_json().encode()
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return {"iv": base64.b64encode(iv).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}

def main():
    with open(CLIENT_CERT_PATH, "rb") as f:
        client_cert = x509.load_pem_x509_certificate(f.read())

    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 5000))

    # Step 1: Send ClientHello
    hello = ClientHello(
        type="hello",
        client_cert=client_cert.public_bytes(serialization.Encoding.PEM).decode(),
        nonce=base64.b64encode(b"client_nonce").decode()
    )
    client.sendall(hello.model_dump_json(by_alias=True).encode())

    # Step 2: Receive ServerHello
    data = json.loads(client.recv(4096).decode())
    server_hello = ServerHello.model_validate(data)
    server_cert = x509.load_pem_x509_certificate(server_hello.server_cert.encode())

    # Verify cert
    try:
        ca_cert.public_key().verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server_cert.signature_hash_algorithm
        )
    except Exception as e:
        print("BAD CERT:", e)
        return

    print("Server certificate verified!")

    # Step 3: DH exchange
    # Generate DH parameters
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g

    # Generate client private key
    client_private_key = parameters.generate_private_key()
    A = client_private_key.public_key().public_numbers().y  # g^a mod p

    # Send DH parameters and client public key
    client_dh_msg = ClientDH(type="dh client", g=g, p=p, A=A)
    client.sendall(client_dh_msg.model_dump_json().encode())

    # Receive server's public key B
    server_data = json.loads(client.recv(4096).decode())
    server_dh = ServerDH.model_validate(server_data)
    B = server_dh.B

    # Compute shared secret: K = B^a mod p
    shared_key_int = pow(B, client_private_key.private_numbers().x, p)
    Ks = hashlib.sha256(shared_key_int.to_bytes((shared_key_int.bit_length() + 7) // 8, "big")).digest()[:16]
    print("Shared AES key (hex):", Ks.hex())

    # Collect and encrypt registration credentials
    auth_choice = show_auth_menu()
    credentials = collect_credentials(auth_choice)
    encrypted_payload = encrypt_payload(Ks, credentials)

    client.sendall(json.dumps({"type": "auth_data", "payload": encrypted_payload}).encode())
    response = json.loads(client.recv(4096).decode())
    try:
        if auth_choice == "register":
            server_resp = ServerRegisterResponse.model_validate(response)
            if server_resp.status == "ok":
                print(f"Registration successful!")
            else:
                print(f"Registration failed: {server_resp.status}")
        else:  # login
            server_resp = ServerLoginResponse.model_validate(response)
            if server_resp.status == "ok":
                print("Login successful!")
            else:
                print("Login failed!")
    except Exception as e:
        print("Failed to parse server response:", e)

    print(server_resp)

    client.close()

if __name__ == "__main__":
    main()
