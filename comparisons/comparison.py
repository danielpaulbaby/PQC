import time
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
import nested
import comparisons.hybrid_simple as simple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
 
 
def time_it(fn, *args, repeats=20, **kwargs):
    start = time.perf_counter()
    result = None
    for _ in range(repeats):
        result = fn(*args, **kwargs)
    elapsed = (time.perf_counter() - start) / repeats
    return result, elapsed * 1000  # ms
 
 
def strip_ecdsa_component(module_name, sig, category):
    if module_name == "nested":
        import struct
        (mldsa_len,) = struct.unpack(">I", sig[:4])
        offset = 4 + mldsa_len
        (ecdsa_len,) = struct.unpack(">H", sig[offset:offset + 2])
        offset += 2
        return sig[offset:offset + ecdsa_len]
    else:
        import struct
        (ecdsa_len,) = struct.unpack(">H", sig[:2])
        return sig[2:2 + ecdsa_len]
 
 
def run_comparison(category: str):
    print(f"===== {category} =====\n")
    msg = b"benchmark comparison message"
 
    for label, module in (("NESTED", nested), ("SIMPLE", simple)):
        kp, keygen_ms = time_it(module.hybrid_keygen, category=category, repeats=5)
        sig, sign_ms = time_it(module.hybrid_sign, kp.ecdsa_private, kp.mldsa_private, msg, category=category, repeats=20)
        ok, verify_ms = time_it(module.hybrid_verify, kp.ecdsa_public, kp.mldsa_public, sig, msg, category=category, repeats=20)
 
        print(f"[{label}]")
        print(f"  combined signature size : {len(sig)} bytes")
        print(f"  keygen  : {keygen_ms:.2f} ms")
        print(f"  sign    : {sign_ms:.2f} ms")
        print(f"  verify  : {verify_ms:.2f} ms  (correct sig verifies: {ok})")
 
        ecdsa_component = strip_ecdsa_component("nested" if label == "NESTED" else "simple", sig, category)
        try:
            kp.ecdsa_public.verify(ecdsa_component, msg, ec.ECDSA(module.CATEGORIES[category].crypto_hash))
            standalone_valid = True
        except InvalidSignature:
            standalone_valid = False
        print(f"  ECDSA component alone verifies as standalone signature over the plain message: {standalone_valid}")
        print()
 
 
if __name__ == "__main__":
    run_comparison("category1")
    run_comparison("category3")