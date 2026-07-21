from __future__ import annotations
 
import datetime
import struct
 
from cryptography import x509
from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
 
import nested
 
# Custom, project-specific extension OID -- NOT IANA-registered.
HYBRID_EXTENSION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
 
 
def _canonical_payload(
    ecdsa_public: ec.EllipticCurvePublicKey,
    mldsa_public: bytes,
    subject_common_name: str,
    serial_number: int,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
) -> bytes:
    """
    Fixed, extension-independent payload the hybrid signature covers.
    Built the same way at encode time and verify time -- never from
    tbs_certificate_bytes, to avoid the circular-dependency bug this
    module originally hit.
    """
    ecdsa_pub_der = ecdsa_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    name_bytes = subject_common_name.encode("utf-8")
 
    serial_bytes = serial_number.to_bytes((serial_number.bit_length() + 7) // 8 or 1, "big")
 
    parts = [
        struct.pack(">I", len(ecdsa_pub_der)), ecdsa_pub_der,
        struct.pack(">I", len(mldsa_public)), mldsa_public,
        struct.pack(">I", len(name_bytes)), name_bytes,
        struct.pack(">I", len(serial_bytes)), serial_bytes,
        not_before.isoformat().encode("ascii"),
        not_after.isoformat().encode("ascii"),
    ]
    return b"".join(parts)
 
 
def encode_certificate(
    kp: nested.HybridKeyPair,
    subject_common_name: str,
    category: str = nested.DEFAULT_CATEGORY,
    valid_days: int = 365,
) -> bytes:
    """Builds a self-signed hybrid certificate. Returns PEM bytes."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name),
    ])
 
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    not_after = now + datetime.timedelta(days=valid_days)
    serial = x509.random_serial_number()
 
    payload = _canonical_payload(
        kp.ecdsa_public, kp.mldsa_public, subject_common_name, serial, now, not_after
    )
    hybrid_sig = nested.hybrid_sign(kp.ecdsa_private, kp.mldsa_private, payload, category=category)
 
    ext_value = (
        struct.pack(">I", len(kp.mldsa_public)) + kp.mldsa_public
        + struct.pack(">I", len(hybrid_sig)) + hybrid_sig
    )
 
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(kp.ecdsa_public)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.UnrecognizedExtension(HYBRID_EXTENSION_OID, ext_value), critical=False)
    )
    cert = builder.sign(private_key=kp.ecdsa_private, algorithm=crypto_hashes.SHA384())
 
    return cert.public_bytes(serialization.Encoding.PEM)
 
 
def parse_hybrid_extension(cert: x509.Certificate) -> tuple[bytes, bytes]:
    """Extracts (mldsa_public_key, hybrid_signature) from the custom extension."""
    ext = cert.extensions.get_extension_for_oid(HYBRID_EXTENSION_OID)
    value = ext.value.value
 
    offset = 0
    (mldsa_len,) = struct.unpack(">I", value[offset:offset + 4])
    offset += 4
    mldsa_public = value[offset:offset + mldsa_len]
    offset += mldsa_len
 
    (sig_len,) = struct.unpack(">I", value[offset:offset + 4])
    offset += 4
    hybrid_sig = value[offset:offset + sig_len]
 
    return mldsa_public, hybrid_sig
 
 
def verify_certificate(pem_bytes: bytes, category: str = nested.DEFAULT_CATEGORY) -> dict:
    """
    Full hybrid verification. Returns a dict of individual check results
    plus an overall 'valid' bool, so a caller/report can see which layer
    failed, not just pass/fail.
    """
    cert = x509.load_pem_x509_certificate(pem_bytes)
    ecdsa_public = cert.public_key()
 
    results = {}
 
    try:
        ecdsa_public.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        results["classical_x509_signature_valid"] = True
    except InvalidSignature:
        results["classical_x509_signature_valid"] = False
 
    try:
        mldsa_public, hybrid_sig = parse_hybrid_extension(cert)
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        payload = _canonical_payload(
            ecdsa_public, mldsa_public, subject_cn,
            cert.serial_number, cert.not_valid_before_utc, cert.not_valid_after_utc,
        )
        results["hybrid_signature_valid"] = nested.hybrid_verify(
            ecdsa_public, mldsa_public, hybrid_sig, payload, category=category
        )
    except Exception as e:
        results["hybrid_signature_valid"] = False
        results["hybrid_signature_error"] = repr(e)
 
    results["valid"] = results.get("classical_x509_signature_valid", False) and results.get("hybrid_signature_valid", False)
    return results
 
 
if __name__ == "__main__":
    kp = nested.hybrid_keygen(category="category3")
    pem = encode_certificate(kp, subject_common_name="pqc-pilot.example.internal", category="category3")
 
    with open("hybrid_cert.pem", "wb") as f:
        f.write(pem)
 
    print("Certificate written to hybrid_cert.pem")
    print(f"PEM size: {len(pem)} bytes\n")
 
    result = verify_certificate(pem, category="category3")
    print("Verification result:", result)
 
    # Tamper test: flip a byte inside the certificate's extension data
    # (simulating a corrupted/forged cert) and confirm it's rejected.
    tampered_pem = pem.replace(b"MI", b"NJ", 1)  # crude corruption of the base64 body
    try:
        tampered_result = verify_certificate(tampered_pem, category="category3")
    except Exception as e:
        tampered_result = {"valid": False, "error": repr(e)}
    print("Tampered certificate result:", tampered_result)