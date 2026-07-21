#test vectors for our specific hybrid implementation was not found so custom test vectors were taken
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from nested import hybrid_keygen, hybrid_sign, hybrid_verify

MSG = b"original message: transfer $100 to account A"
OTHER_MSG = b"tampered message: transfer $100000 to account B"


def split(sig: bytes):
    offset = 0
    (mldsa_len,) = struct.unpack(">I", sig[offset:offset + 4])
    offset += 4
    mldsa_sig = sig[offset:offset + mldsa_len]
    offset += mldsa_len
    (ecdsa_len,) = struct.unpack(">H", sig[offset:offset + 2])
    offset += 2
    ecdsa_sig = sig[offset:offset + ecdsa_len]
    return mldsa_sig, ecdsa_sig


def rejoin(mldsa_sig: bytes, ecdsa_sig: bytes) -> bytes:
    return (
        struct.pack(">I", len(mldsa_sig)) + mldsa_sig
        + struct.pack(">H", len(ecdsa_sig)) + ecdsa_sig
    )


def run_tests():
    results = []

    def check(name, condition):
        results.append((name, condition))
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}")

    kp1 = hybrid_keygen()
    kp2 = hybrid_keygen()  # unrelated keypair, for substitution / wrong-key tests

    sig = hybrid_sign(kp1.ecdsa_private, kp1.mldsa_private, MSG)
    mldsa_sig, ecdsa_sig = split(sig)

    print("Baseline:")
    check("valid signature verifies correctly",
          hybrid_verify(kp1.ecdsa_public, kp1.mldsa_public, sig, MSG) is True)

    # "Changed (tampered) post-quantum signature"
    bad_mldsa = bytes([mldsa_sig[0] ^ 0xFF]) + mldsa_sig[1:]
    tampered_pqc = rejoin(bad_mldsa, ecdsa_sig)
    check("tampered PQC (ML-DSA) signature rejected",
          hybrid_verify(kp1.ecdsa_public, kp1.mldsa_public, tampered_pqc, MSG) is False)

    # "Changed (tampered) classical signature"
    bad_ecdsa = bytes([ecdsa_sig[0] ^ 0xFF]) + ecdsa_sig[1:]
    tampered_classical = rejoin(mldsa_sig, bad_ecdsa)
    check("tampered classical (ECDSA) signature rejected",
          hybrid_verify(kp1.ecdsa_public, kp1.mldsa_public, tampered_classical, MSG) is False)

    # "Wrong / mismatched keys" -- verify a genuinely valid signature
    # against the WRONG keypair's public keys entirely.
    check("verification with wrong (mismatched) public keys rejected",
          hybrid_verify(kp2.ecdsa_public, kp2.mldsa_public, sig, MSG) is False)

    # "Cut-off (truncated) signature file"
    truncated = sig[:-10]
    try:
        result = hybrid_verify(kp1.ecdsa_public, kp1.mldsa_public, truncated, MSG)
        check("truncated signature rejected cleanly (no crash)", result is False)
    except Exception as e:
        check(f"truncated signature rejected cleanly (no crash) -- RAISED {e!r} instead", False)

    print("\nAdditional tests (beyond the doc's minimum checklist):")

    check("tampered message rejected",
          hybrid_verify(kp1.ecdsa_public, kp1.mldsa_public, sig, OTHER_MSG) is False)

    sig2 = hybrid_sign(kp2.ecdsa_private, kp2.mldsa_private, MSG)
    mldsa_sig2, _ = split(sig2)
    substituted = rejoin(mldsa_sig2, ecdsa_sig)
    check("PQC component substituted from a different keypair rejected (proves nesting binds them)",
          hybrid_verify(kp1.ecdsa_public, kp1.mldsa_public, substituted, MSG) is False)

    # Reordering: swap the two components' positions in the byte layout.
    reordered = struct.pack(">I", len(ecdsa_sig)) + ecdsa_sig + struct.pack(">H", len(mldsa_sig)) + mldsa_sig
    try:
        result = hybrid_verify(kp1.ecdsa_public, kp1.mldsa_public, reordered, MSG)
        check("reordered components rejected cleanly (no crash)", result is False)
    except Exception as e:
        check(f"reordered components rejected cleanly (no crash) -- RAISED {e!r} instead", False)

    print()
    total = len(results)
    passed = sum(1 for _, ok in results if ok)
    print(f"{passed}/{total} should-fail tests passed")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
