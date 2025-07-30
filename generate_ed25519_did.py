import base58
import json
import sys
import subprocess
import base64

from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

# 1. Generate an Ed25519 key pair
signing_key = SigningKey.generate()
verify_key = signing_key.verify_key
public_key_bytes = verify_key.encode(encoder=RawEncoder)
private_key_bytes = signing_key.encode()

# 2. Encode the public key as Multibase base58btc (starts with "z")
multibase_key = "z" + base58.b58encode(public_key_bytes).decode("utf-8")

# 2.1 Output the private key in base64 format
private_key_b64 = base64.urlsafe_b64encode(private_key_bytes).decode("utf-8").rstrip("=")
public_key_b64 = base64.urlsafe_b64encode(public_key_bytes).decode("utf-8").rstrip("=")

print("✅ Ed25519 key pair generated successfully!")
print(f"🔐 Private Key (Base64): {private_key_b64}")
print(f"🔑 Public Key (Base64): {public_key_b64}")
print("🔐 Keep your private key safe and secure!")


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
            "publicKeyMultibase": multibase_key
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
