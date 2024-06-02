# source: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
ca_public_key = ca_private_key.public_key()

with open("ca_private_key.pem", "wb") as f:
    f.write(ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("ca_public_key.pem", "wb") as f:
    f.write(ca_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))


