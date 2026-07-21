"""
ecdsa_component.py

Classical component of the hybrid ECDSA x ML-DSA (Dilithium) signature scheme.
secp256k1 + SHA-256.

Note: secp256k1 is not a NIST/CNSA 2.0 curve and is not universally
supported by X.509/PKI tooling (it's the Bitcoin/Ethereum curve). If
step 4 (certificate packaging) hits compatibility issues with standard
CA/X.509 libraries, that's the likely cause -- flag it in the report
rather than debugging it as a bug.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

CURVE = ec.SECP256K1()
DIGEST = hashes.SHA256()


@dataclass
class ECDSAKeyPair:
    private_key: EllipticCurvePrivateKey
    public_key: EllipticCurvePublicKey


def generate_keypair() -> ECDSAKeyPair:
    priv = ec.generate_private_key(CURVE)
    return ECDSAKeyPair(private_key=priv, public_key=priv.public_key())


def sign(private_key: EllipticCurvePrivateKey, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(DIGEST))


def verify(public_key: EllipticCurvePublicKey, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(DIGEST))
        return True
    except InvalidSignature:
        return False


def private_key_to_pem(private_key: EllipticCurvePrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_key_from_pem(pem_bytes: bytes) -> EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem_bytes, password=None)


def public_key_from_pem(pem_bytes: bytes) -> EllipticCurvePublicKey:
    return serialization.load_pem_public_key(pem_bytes)


if __name__ == "__main__":
    msg = b"Hi hello signature testing"

    kp = generate_keypair()
    sig = sign(kp.private_key, msg)

    print(f"Signature length: {len(sig)} bytes (DER)")
    print("Verify (correct message):   ", verify(kp.public_key, sig, msg))
    print("Verify (tampered message):  ", verify(kp.public_key, sig, b"tampered"))
    print("Verify (tampered signature):", verify(kp.public_key, bytes([sig[0] ^ 0xFF]) + sig[1:], msg))

    priv_pem = private_key_to_pem(kp.private_key)
    pub_pem = public_key_to_pem(kp.public_key)
    reloaded_pub = public_key_from_pem(pub_pem)
    print("Verify after PEM round-trip:", verify(reloaded_pub, sig, msg))