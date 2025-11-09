"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import os
import argparse
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import DNSName, SubjectAlternativeName

# ----- 1. Parse command-line arguments -----
parser = argparse.ArgumentParser(description="Generate a server/client certificate signed by Root CA")
parser.add_argument("--cn", type=str, required=True, help="Common Name (CN) for the certificate")
parser.add_argument("--entity", type=str, required=True, choices=["server", "client"],
                    help="Entity type: server or client")
args = parser.parse_args()

cn = args.cn
entity = args.entity

# ----- 2. Set paths -----
# Folder where all certificates are stored (same as gen_ca.py)
certs_dir = "/mnt/c/Users/Home/Documents/uni/sem7/InfoSec/A2/securechat-skeleton/certs"
os.makedirs(certs_dir, exist_ok=True)

# Output key/cert paths
key_path = os.path.join(certs_dir, f"{entity}.key")
cert_path = os.path.join(certs_dir, f"{entity}.crt")

# Root CA paths
ca_key_path = os.path.join(certs_dir, "ca.key")
ca_cert_path = os.path.join(certs_dir, "ca.crt")

# ----- 3. Load Root CA -----
with open(ca_key_path, "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=b"23#infoSec")

with open(ca_cert_path, "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# ----- 4. Generate entity's private key -----
entity_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

# ----- 5. Build certificate -----
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST"),
    x509.NameAttribute(NameOID.COMMON_NAME, cn),
])

# SAN = CN
san = SubjectAlternativeName([DNSName(cn)])

entity_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)
    .public_key(entity_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))  # 10 years
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(san, critical=False)
    .sign(private_key=ca_key, algorithm=hashes.SHA256())
)

# ----- 6. Save private key -----
with open(key_path, "wb") as f:
    f.write(
        entity_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"23#infoSec")
        )
    )

# ----- 7. Save certificate -----
with open(cert_path, "wb") as f:
    f.write(entity_cert.public_bytes(serialization.Encoding.PEM))

print(f"{entity.capitalize()} certificate and key created successfully!")
print("Private key:", key_path)
print("Certificate:", cert_path)
