from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

import oqs

import ecdsa as ecdsa_lib
from ecdsa.util import sigencode_der
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.exceptions import InvalidSignature

@dataclass(frozen=True)
class CategoryParams:
    label: bytes
    ecdsa_curve: object          # cryptography curve instance
    ecdsa_lib_curve: object      # matching `ecdsa` library curve
    hashfunc: object             # hashlib function, e.g. hashlib.sha384
    crypto_hash: object          # matching cryptography hash instance
    mldsa_algorithm: str


CATEGORIES = {
    "category1": CategoryParams(
        label=b"HYBRID-STRONG-NESTING-MLDSA44-ECDSA-P256-v1",
        ecdsa_curve=ec.SECP256R1(),
        ecdsa_lib_curve=ecdsa_lib.NIST256p,
        hashfunc=hashlib.sha256,
        crypto_hash=crypto_hashes.SHA256(),
        mldsa_algorithm="ML-DSA-44",
    ),
    "category3": CategoryParams(
        label=b"HYBRID-STRONG-NESTING-MLDSA87-ECDSA-P384-v1",
        ecdsa_curve=ec.SECP384R1(),
        ecdsa_lib_curve=ecdsa_lib.NIST384p,
        hashfunc=hashlib.sha384,
        crypto_hash=crypto_hashes.SHA384(),
        mldsa_algorithm="ML-DSA-87",
    ),
}

DEFAULT_CATEGORY = "category3"

@dataclass
class HybridKeyPair:
    ecdsa_public: EllipticCurvePublicKey
    ecdsa_private: EllipticCurvePrivateKey
    mldsa_public: bytes
    mldsa_private: bytes

def _ecdsa_generate_keypair(params: CategoryParams):
    priv = ec.generate_private_key(params.ecdsa_curve)
    return priv, priv.public_key()


def _ecdsa_sign(params: CategoryParams, private_key: EllipticCurvePrivateKey, message: bytes) -> bytes:
    d = private_key.private_numbers().private_value
    sk = ecdsa_lib.SigningKey.from_secret_exponent(d, curve=params.ecdsa_lib_curve)
    return sk.sign_deterministic(message, hashfunc=params.hashfunc, sigencode=sigencode_der)


def _ecdsa_verify(params: CategoryParams, public_key: EllipticCurvePublicKey, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(params.crypto_hash))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False

def _mldsa_generate_keypair(params: CategoryParams):
    with oqs.Signature(params.mldsa_algorithm) as signer:
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
    return pk, sk


def _mldsa_sign(params: CategoryParams, private_key: bytes, message: bytes) -> bytes:
    with oqs.Signature(params.mldsa_algorithm, secret_key=private_key) as signer:
        return signer.sign(message)


def _mldsa_verify(params: CategoryParams, public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        with oqs.Signature(params.mldsa_algorithm) as verifier:
            return verifier.verify(message, signature, public_key)
    except Exception:
        return False

def hybrid_keygen(category: str = DEFAULT_CATEGORY) -> HybridKeyPair:
    params = CATEGORIES[category]
    ecdsa_priv, ecdsa_pub = _ecdsa_generate_keypair(params)
    mldsa_pub, mldsa_priv = _mldsa_generate_keypair(params)
    return HybridKeyPair(
        ecdsa_public=ecdsa_pub,
        ecdsa_private=ecdsa_priv,
        mldsa_public=mldsa_pub,
        mldsa_private=mldsa_priv,
    )


def _binder_hash(params: CategoryParams, message: bytes, mldsa_sig: bytes) -> bytes:
    binder = params.label + struct.pack(">I", len(message)) + message + mldsa_sig
    return params.hashfunc(binder).digest()


def hybrid_sign(
    ecdsa_private: EllipticCurvePrivateKey,
    mldsa_private: bytes,
    message: bytes,
    category: str = DEFAULT_CATEGORY,
) -> bytes:
    params = CATEGORIES[category]

    mldsa_sig = _mldsa_sign(params, mldsa_private, message)
    h = _binder_hash(params, message, mldsa_sig)
    ecdsa_sig = _ecdsa_sign(params, ecdsa_private, h)

    return (
        struct.pack(">I", len(mldsa_sig)) + mldsa_sig
        + struct.pack(">H", len(ecdsa_sig)) + ecdsa_sig
    )


def hybrid_verify(
    ecdsa_public: EllipticCurvePublicKey,
    mldsa_public: bytes,
    combined_signature: bytes,
    message: bytes,
    category: str = DEFAULT_CATEGORY,
) -> bool:
    params = CATEGORIES[category]

    try:
        offset = 0
        (mldsa_len,) = struct.unpack(">I", combined_signature[offset:offset + 4])
        offset += 4
        mldsa_sig = combined_signature[offset:offset + mldsa_len]
        offset += mldsa_len

        (ecdsa_len,) = struct.unpack(">H", combined_signature[offset:offset + 2])
        offset += 2
        ecdsa_sig = combined_signature[offset:offset + ecdsa_len]
        offset += ecdsa_len

        if offset != len(combined_signature):
            return False
    except (struct.error, IndexError):
        return False

    h = _binder_hash(params, message, mldsa_sig)

    ecdsa_ok = _ecdsa_verify(params, ecdsa_public, ecdsa_sig, h)
    mldsa_ok = _mldsa_verify(params, mldsa_public, mldsa_sig, message)

    return ecdsa_ok and mldsa_ok


if __name__ == "__main__":
    msg = b"hi hello hybrid signature testing"

    for category in ("category1", "category3"):
        print(f"--- {category} ---")
        kp = hybrid_keygen(category=category)
        sig = hybrid_sign(kp.ecdsa_private, kp.mldsa_private, msg, category=category)

        print(f"Combined signature length: {len(sig)} bytes")
        print("Verify (correct message):  ", hybrid_verify(kp.ecdsa_public, kp.mldsa_public, sig, msg, category=category))
        print("Verify (tampered message): ", hybrid_verify(kp.ecdsa_public, kp.mldsa_public, sig, b"tampered", category=category))

        params = CATEGORIES[category]
        fixed_hash = params.hashfunc(b"fixed test input").digest()
        sig_a = _ecdsa_sign(params, kp.ecdsa_private, fixed_hash)
        sig_b = _ecdsa_sign(params, kp.ecdsa_private, fixed_hash)
        print("RFC 6979 determinism (ECDSA component, fixed input):", sig_a == sig_b)
        print()