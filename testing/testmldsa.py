#test vectors taken from wycheproof github repo
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dilithium import verify

PARAMETER_SET = "ML-DSA-44"
PRE_HASH = "pure"
SIGNATURE_INTERFACE = "external"
EXTERNAL_MU = False


def run(vector_path: str) -> None:
    with open(vector_path) as f:
        data = json.load(f)

    assert data["algorithm"] == "ML-DSA"

    matching_groups = [
        g for g in data["testGroups"]
        if g["parameterSet"] == PARAMETER_SET
        and g["preHash"] == PRE_HASH
        and g["signatureInterface"] == SIGNATURE_INTERFACE
        and g["externalMu"] == EXTERNAL_MU
    ]

    if not matching_groups:
        print(f"No test groups found matching {PARAMETER_SET}/{PRE_HASH}/{SIGNATURE_INTERFACE}.")
        sys.exit(1)

    total = 0
    passed = 0
    correct=0
    wrong=0
    failed = []

    for group in matching_groups:
        for test in group["tests"]:
            total += 1
            tc_id = test["tcId"]
            pk = bytes.fromhex(test["pk"])
            message = bytes.fromhex(test["message"])
            signature = bytes.fromhex(test["signature"])
            context = bytes.fromhex(test["context"]) if test.get("context") else b""
            expected = test["testPassed"]

            got = verify(pk, signature, message, context)

            if got == expected:
                passed += 1
                wrong=wrong+1 if got==False else wrong
                correct=correct+1 if got==True else correct
            else:
                failed.append((tc_id, test.get("reason", ""), expected, got))

    print(f"{passed}/{total} test cases passed ({PARAMETER_SET}, {PRE_HASH}, {SIGNATURE_INTERFACE})")
    print(f"Valid: {correct}, Invalid: {wrong} Test cases verified")
    if failed:
        print(f"\n{len(failed)} FAILURES:")
        for tc_id, reason, expected, got in failed:
            print(f"  tcId={tc_id}  expected={expected}  got={got}  ({reason})")
        sys.exit(1)
    else:
        print("All vectors matched expected result.")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "testing/internalProjection.json"
    run(path)