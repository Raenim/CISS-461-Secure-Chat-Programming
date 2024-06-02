from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def create_certificate(username, ca_private_key):
    with open(username + ".cert", "wb") as f:
        f.write(ca_private_key.sign(
            username.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        ))


with open("ca_private_key.pem", "rb") as f:
    ca_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

for username in ["Alice", "Bob", "Charlie"]:
    create_certificate(username, ca_private_key)