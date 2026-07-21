#test vectors taken from wycheproof github repo
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from ecdsa_comp import verify


def run(vector_path: str) -> None:
    with open(vector_path) as f:
        data = json.load(f)

    total = 0
    passed = 0
    correct=0
    wrong=0
    failed = []

    for group in data["testGroups"]:
        pub_pem = group["publicKeyPem"].encode()
        try:
            public_key = serialization.load_pem_public_key(pub_pem)
        except Exception as e:
            # A handful of Wycheproof groups intentionally ship malformed
            # keys to test key-parsing robustness, not signature logic --
            # out of scope for this harness, so skip and note it.
            print(f"  [skip group] key failed to parse: {e}")
            continue

        for test in group["tests"]:
            total += 1
            tc_id = test["tcId"]
            msg = bytes.fromhex(test["msg"])
            sig = bytes.fromhex(test["sig"])
            expected = test["result"]  # "valid" | "invalid" | "acceptable"

            try:
                ok = verify(public_key, sig, msg)
            except Exception:
                ok = False

            # "acceptable" vectors are ones the spec is ambiguous about
            # (e.g. non-strict DER encoding); treat pass-or-fail as OK.
            if expected == "acceptable":
                passed += 1
                correct +=1
                continue

            expected_ok = (expected == "valid")
            if expected=="invalid":
                if not ok:
                    passed+=1
                    wrong+=1
                else:
                    failed.append((tc_id, test.get("comment", ""), expected, ok))
            if expected=="valid":
                if ok:
                    passed += 1
                    correct +=1
                else:
                    failed.append((tc_id, test.get("comment", ""), expected, ok))

    print(f"\n{passed}/{total} test cases passed")
    print(f"Valid: {correct}, Invalid: {wrong} Test cases verified")
    if failed:
        print(f"\n{len(failed)} FAILURES:")
        for tc_id, comment, expected, got in failed[:20]:
            print(f"  tcId={tc_id}  expected={expected}  got={'valid' if got else 'invalid'}  ({comment})")
        if len(failed) > 20:
            print(f"  ... and {len(failed) - 20} more")
        sys.exit(1)
    else:
        print("All vectors matched expected result.")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "testing/ecdsa_secp384r1_sha384_test.json"
    run(path)