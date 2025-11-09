"""Show results of certificate inspection."""  

from cryptography import x509

cert_path = r"C:\Users\Home\Documents\uni\sem7\InfoSec\A2\securechat-skeleton\certs\server.crt"

with open(cert_path, "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())

print("Subject:", cert.subject)
print("Issuer:", cert.issuer)
print("Validity:", cert.not_valid_before_utc, "-", cert.not_valid_after_utc)
print("SAN:", cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
