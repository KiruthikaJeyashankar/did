from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import base64
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Base64URL encode (no padding)
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

# Generate Ed25519 key pair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Raw bytes
private_key_raw = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

public_key_raw = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Convert to Base64URL
x = base64url_encode(public_key_raw)
d = base64url_encode(private_key_raw)

# Public JWK
public_jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": x,
    "alg": "EdDSA",
    "key_ops": ["verify"],
    "use": "sig"
}

# Public key in pem format
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# print("🔑 Public Key (PEM):\n", public_key_pem)
print("🔑 Public Key (PEM):\n", public_key_pem.decode("utf-8"))

# Public key in Hex format
public_key_hex = public_key_raw.hex()
print(f"🔑 Public Key (Hex): {public_key_hex}")

# Private JWK (includes "d" for private key)
private_jwk = {
    **public_jwk,
    "key_ops": ["sign"],
    "d": d
}

# Pretty print JWKs
print("🔐 Private JWK:\n", json.dumps(private_jwk, indent=2))
print("\n🔓 Public JWK:\n", json.dumps(public_jwk, indent=2))

private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)
private_key_b64 = base64.b64encode(private_key_bytes).decode("utf-8")

# Export public key in raw format and encode to base64
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
public_key_b64 = base64.b64encode(public_key_bytes).decode("utf-8")

print(f"🔐 Private Key (Base64): {private_key_b64}")
print(f"🔑 Public Key (Base64): {public_key_b64}")

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
            # "publicKeyJwk": public_jwk
            # "publicKeyPem": public_key_pem.decode("utf-8")
            "publicKeyHex": public_key_hex
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
