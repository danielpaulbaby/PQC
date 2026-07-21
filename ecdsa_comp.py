from __future__ import annotations
 
import hashlib
from dataclasses import dataclass
 
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
 
import ecdsa as ecdsa_lib
from ecdsa.util import sigencode_der
 
CURVE = ec.SECP384R1()
DIGEST = hashes.SHA384()
_HASHFUNC = hashlib.sha384  # must match DIGEST above
 
 
@dataclass
class ECDSAKeyPair:
    private_key: EllipticCurvePrivateKey
    public_key: EllipticCurvePublicKey
 
 
def generate_keypair() -> ECDSAKeyPair:
    priv = ec.generate_private_key(CURVE)
    return ECDSAKeyPair(private_key=priv, public_key=priv.public_key())
 
 
def sign(private_key: EllipticCurvePrivateKey, message: bytes) -> bytes:
    # Extract the raw private scalar (d) and hand it to the `ecdsa` library,
    # which implements RFC 6979 deterministic nonce derivation. The output
    # is a standard DER-encoded (r, s) signature -- identical wire format
    # to what cryptography's own .sign() would have produced, just with a
    # deterministic rather than random nonce.
    d = private_key.private_numbers().private_value
    sk = ecdsa_lib.SigningKey.from_secret_exponent(d, curve=ecdsa_lib.NIST384p)
    return sk.sign_deterministic(message, hashfunc=_HASHFUNC, sigencode=sigencode_der)
 
 
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
    msg = b"hybrid PKI pilot: test message"
 
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
 