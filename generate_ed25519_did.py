import base58
import json
import sys
import subprocess
import base64

from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Generate a new Ed25519 private key
private_key = ed25519.Ed25519PrivateKey.generate()

# Obtain the corresponding public key
public_key = private_key.public_key()

# Serialize the private key to bytes (e.g., PEM format)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()  # Use NoEncryption for unencrypted keys
)

# Serialize the public key to bytes (e.g., PEM format)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Private Key (PEM format):\n", private_pem.decode())
print("\nPublic Key (PEM format):\n", public_pem.decode())

# Example of serializing to raw bytes (32 bytes for public key)
public_raw_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# # 1. Generate an Ed25519 key pair
# signing_key = SigningKey.generate()
# verify_key = signing_key.verify_key
# public_key_bytes = verify_key.encode(encoder=RawEncoder)
# private_key_bytes = signing_key.encode()

# # 2. Encode the public key as Multibase base58btc (starts with "z")
# multibase_key = "z" + base58.b58encode(public_key_bytes).decode("utf-8")

# # 2.1 Output the private key in base64 format
# # private_key_b64 = base64.urlsafe_b64encode(private_key_bytes).decode("utf-8").rstrip("=")
# # private_key_b64 = base64.b64encode(private_key_bytes).decode("utf-8").rstrip("=")
# public_key_b64 = base64.urlsafe_b64encode(public_key_bytes).decode("utf-8").rstrip("=")


# print("✅ Ed25519 key pair generated successfully!")
# print("🔐 Keep your private key safe and secure!")

# #  Create JWK structure
# jwk = {
#     "kty": "OKP",
#     "crv": "Ed25519",
#     "x": public_key_b64,
#     "alg": "EdDSA",
#     # "key_ops": ["sign", "verify"],
#     # "use": "sig"
# }
# 3. Create JWK structure
public_key_base64 = base64.urlsafe_b64encode(public_raw_bytes).decode("utf-8").rstrip("=")
private_key_b64 = base64.urlsafe_b64encode(private_pem).decode("utf-8").rstrip("=")
jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": public_key_base64,
    "alg": "EdDSA",
    # "key_ops": ["sign", "verify"],
    # "use": "sig"
}

print(f"🔐 Private Key (Base64): {private_key_b64}")
print(f"🔑 Public Key (Base64): {public_key_base64}")

# 3. Define your DID
domain = "KiruthikaJeyashankar.github.io:did"
did = f"did:web:{domain}"
key_id = f"{did}#key-1"

# 4. Build the DID Document
did_document = {
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": did,
    "verificationMethod": [
        {
            "id": key_id,
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            # "publicKeyMultibase": multibase_key
            "publicKeyJwk": jwk
        }
    ],
    "assertionMethod": [
        key_id
    ]
}

# 5. Save to `did.json`
with open("did.json", "w") as f:
    json.dump(did_document, f, indent=2)

print("✅ did.json generated successfully!")
print(f"🌐 Host this at: https://{domain}/.well-known/did.json")

print(f"📄 DID Document: {did}")
print(f"🔗 Key ID: {key_id}")
