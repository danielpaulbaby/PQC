from __future__ import annotations
 
from dataclasses import dataclass
 
import oqs
 
ALGORITHM = "ML-DSA-44"
 
 
@dataclass
class MLDSAKeyPair:
    public_key: bytes
    private_key: bytes
 
 
def generate_keypair() -> MLDSAKeyPair:
    with oqs.Signature(ALGORITHM) as signer:
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
    return MLDSAKeyPair(public_key=pk, private_key=sk)
 
 
def sign(private_key: bytes, message: bytes, context: bytes = b"") -> bytes:
    # context is FIPS 204's domain-separation string (max 255 bytes) --
    # relevant later for the hybrid combiner's own domain separation.
    with oqs.Signature(ALGORITHM, secret_key=private_key) as signer:
        return signer.sign_with_ctx_str(message, context)
 
 
def verify(public_key: bytes, signature: bytes, message: bytes, context: bytes = b"") -> bool:
    try:
        with oqs.Signature(ALGORITHM) as verifier:
            return verifier.verify_with_ctx_str(message, signature, context, public_key)
    except Exception:
        return False
 
 
def private_key_to_bytes(private_key: bytes) -> bytes:
    return private_key
 
 
def public_key_to_bytes(public_key: bytes) -> bytes:
    return public_key
 
 
def private_key_from_bytes(data: bytes) -> bytes:
    return data
 
 
def public_key_from_bytes(data: bytes) -> bytes:
    return data
 
 
if __name__ == "__main__":
    msg = b"hybrid PKI pilot: test message"
 
    kp = generate_keypair()
    sig = sign(kp.private_key, msg)
 
    print(f"Public key length:  {len(kp.public_key)} bytes")
    print(f"Private key length: {len(kp.private_key)} bytes")
    print(f"Signature length:   {len(sig)} bytes")
    print("Verify (correct message):   ", verify(kp.public_key, sig, msg))
    print("Verify (tampered message):  ", verify(kp.public_key, sig, b"tampered"))
    print("Verify (tampered signature):", verify(kp.public_key, bytes([sig[0] ^ 0xFF]) + sig[1:], msg))
 
    pub_bytes = public_key_to_bytes(kp.public_key)
    reloaded_pub = public_key_from_bytes(pub_bytes)
    print("Verify after byte round-trip:", verify(reloaded_pub, sig, msg))
 