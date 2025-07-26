import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

def load_rsa_pub_key(b64_str):
    key_bytes = base64.b64decode(b64_str)
    return serialization.load_der_public_key(key_bytes)

def load_rsa_priv_key(b64_str):
    key_bytes = base64.b64decode(b64_str)
    return serialization.load_der_private_key(key_bytes, None)

def load_ecdsa_pub_key(b64_str):
    key_bytes = base64.b64decode(b64_str)
    return serialization.load_der_public_key(key_bytes)

def export_keys_as_string(private_key, public_key):
    _priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    _pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    chaves = {
        "private_key": base64.b64encode(_priv_bytes).decode(),
        "public_key": base64.b64encode(_pub_bytes).decode()
    }

    return chaves

with open("key", "r") as f:
    priv = f.read()

with open("key.pub", "r") as f:
    pub = f.read()

a: RSAPublicKey = load_rsa_pub_key(pub)
b: RSAPrivateKey = load_rsa_priv_key(priv)

k = export_keys_as_string(b, a)

with open("key_py", "w") as f:
    f.write(k['private_key'])

with open("key.pub_py", "w") as f:
    f.write(k['public_key'])
