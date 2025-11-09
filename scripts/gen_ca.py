"""Create Root CA (RSA + self-signed X.509) using cryptography."""  

import os
import argparse
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

# ----- 1. Parse command-line arguments -----
parser = argparse.ArgumentParser(description="Generate a Root CA certificate")
parser.add_argument("--name", type=str, required=True, help="Common Name (CN) for the Root CA")
args = parser.parse_args()
common_name = args.name

# ----- 2. Set output directory (Windows path from WSL) -----
ca_dir = "/mnt/c/Users/Home/Documents/uni/sem7/InfoSec/A2/securechat-skeleton/certs"
os.makedirs(ca_dir, exist_ok=True)

# ----- 3. Generate CA's private RSA key -----
ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

# ----- 4. Build certificate subject/issuer -----
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST"),
    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
])

# ----- 5. Create the certificate -----
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))  # 10 years
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(private_key=ca_key, algorithm=hashes.SHA256())
)

# ----- 6. Save the private key -----
key_path = os.path.join(ca_dir, "ca.key")
with open(key_path, "wb") as f:
    f.write(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"23#infoSec")
        )
    )

# ----- 7. Save the certificate -----
cert_path = os.path.join(ca_dir, "ca.crt")
with open(cert_path, "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

print("Root CA created successfully!")
print("Private key:", key_path)
print("Certificate:", cert_path)
