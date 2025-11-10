"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket, json, base64, logging, os, hashlib, mysql.connector
from cryptography import x509
from cryptography.x509 import DNSName, SubjectAlternativeName
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, dh
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from app.storage.db import get_db_connection
from app.common.protocol import (
    ClientHello,
    ServerHello,
    ClientDH,
    ServerDH,
    ClientRegister,
    ServerRegisterResponse,
    ServerError,
    ClientLogin,
    ServerLoginResponse,
)

SERVER_CERT_PATH = "certs/server.crt"
SERVER_KEY_PATH = "certs/server.key"
CA_CERT_PATH = "certs/ca.crt"

# Configure logging
logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# --- AES DECRYPT ---
def aes_decrypt(ciphertext_b64, key, iv_b64):
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded_plaintext[-1]
    return padded_plaintext[:-pad_len]

# --- HANDLE REGISTRATION ---
def handle_auth(encrypted_payload, aes_key):
    """
    Decrypt AES payload from client, detect if it's registration or login,
    and handle appropriately.
    Returns: Pydantic response (ServerRegisterResponse / ServerLoginResponse / ServerError)
    """
    try:
        payload = encrypted_payload["payload"]
        iv_b64 = payload["iv"]
        ciphertext_b64 = payload["ciphertext"]

        plaintext_bytes = aes_decrypt(ciphertext_b64, aes_key, iv_b64)
        plaintext_str = plaintext_bytes.decode()

        # Try to parse as registration
        try:
            msg = ClientRegister.model_validate_json(plaintext_str)
            is_register = True
        except Exception:
            is_register = False

        if is_register:
            email = msg.email
            username = msg.username
            password = msg.pwd  # raw password

            salt = os.urandom(16)
            pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()

            cnx = get_db_connection()
            cursor = cnx.cursor()
            cursor.execute("SELECT 1 FROM users WHERE username=%s OR email=%s", (username, email))
            if cursor.fetchone():
                cursor.close()
                cnx.close()
                return ServerRegisterResponse(type="Register", status="error")

            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                (email, username, salt, pwd_hash)
            )
            cnx.commit()
            cursor.close()
            cnx.close()

            return ServerRegisterResponse(type="Register", status="ok")

        # Else try to parse as login
        msg = ClientLogin.model_validate_json(plaintext_str)
        email = msg.email
        password = msg.pwd  # raw password
        nonce = msg.nonce  # can verify freshness if needed

        cnx = get_db_connection()
        cursor = cnx.cursor()
        cursor.execute("SELECT salt, pwd_hash FROM users WHERE email=%s", (email,))
        row = cursor.fetchone()
        cursor.close()
        cnx.close()

        if not row:
            return ServerLoginResponse(type="login", status="error")

        salt, stored_hash = row
        computed_hash = hashlib.sha256(salt + password.encode()).hexdigest()

        if computed_hash != stored_hash:
            return ServerLoginResponse(type="login", status="error")

        return ServerLoginResponse(type="login", status="ok")

    except mysql.connector.Error as err:
        print("MySQL Error:", err)
        return ServerError(type="error", message="Database error")
    except Exception as e:
        print("Error in handle_auth:", e)
        return ServerError(type="error", message=str(e))
    
def main():
    with open(SERVER_CERT_PATH, "rb") as f:
        server_cert = x509.load_pem_x509_certificate(f.read())

    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 5000))
    server.listen(1)
    print("Server ready...")

    conn, addr = server.accept()
    print(f"Connected by {addr}")

    # Step 1: Receive ClientHello
    data = json.loads(conn.recv(4096).decode())
    client_hello = ClientHello.model_validate(data)
    client_cert = x509.load_pem_x509_certificate(client_hello.client_cert.encode())

    # 1a. Verify certificate signature
    try:
        ca_cert.public_key().verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            client_cert.signature_hash_algorithm
        )
    except Exception as e:
        msg = f"BAD CERT: signature invalid - {e}"
        print(msg)
        conn.sendall(ServerError(type="error", message=msg).model_dump_json().encode())
        conn.close()
        return

    # 1b. Validity period check
    now = datetime.now(timezone.utc)
    if now < client_cert.not_valid_before_utc or now > client_cert.not_valid_after_utc:
        msg = "BAD CERT: expired or not yet valid"
        conn.sendall(ServerError(type="error", message=msg).model_dump_json().encode())
        conn.close()
        return

    # 1c. SAN check
    expected_san = "client.local"
    try:
        san_ext = client_cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        san_dns = san_ext.get_values_for_type(DNSName)
    except x509.ExtensionNotFound:
        san_dns = []

    if expected_san not in san_dns:
        msg = f"BAD CERT: SAN mismatch, expected {expected_san}"
        conn.sendall(ServerError(type="error", message=msg).model_dump_json().encode())
        conn.close()
        return

    print("Client certificate verified!")

    # Step 2: Send ServerHello
    nonce = base64.b64encode(b"server_nonce").decode()
    server_hello = ServerHello(
        type="server hello",
        server_cert=server_cert.public_bytes(serialization.Encoding.PEM).decode(),
        nonce=nonce
    )
    conn.sendall(server_hello.model_dump_json(by_alias=True).encode())

    # Step 3: DH exchange
    client_data = json.loads(conn.recv(4096).decode())
    client_dh = ClientDH.model_validate(client_data)

    p, g, A = client_dh.p, client_dh.g, client_dh.A

    # Generate server private key
    parameters = dh.DHParameterNumbers(p, g).parameters()
    server_private_key = parameters.generate_private_key()
    B = server_private_key.public_key().public_numbers().y  # g^b mod p

    # Send server public key
    server_dh_msg = ServerDH(type="dh server", B=B)
    conn.sendall(server_dh_msg.model_dump_json().encode())

    # Compute shared secret: K = A^b mod p
    shared_key_int = pow(A, server_private_key.private_numbers().x, p)
    Ks = hashlib.sha256(shared_key_int.to_bytes((shared_key_int.bit_length() + 7) // 8, "big")).digest()[:16]
    print("Shared AES key (hex):", Ks.hex())

    encrypted_payload = json.loads(conn.recv(4096).decode())
    response = handle_auth(encrypted_payload, Ks)
    conn.sendall(response.model_dump_json().encode())

    conn.close()

if __name__ == "__main__":
    main()
