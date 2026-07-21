import oqs

def run_mldsa_demo():
    # 1. Choose the Dilithium variant (ML-DSA)
    # Options include: "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    sig_alg = "ML-DSA-65"
    
    print(f"--- Testing {sig_alg} (Standardized Dilithium) ---")
    
    # Check if the algorithm is enabled in your liboqs build
    if sig_alg not in oqs.get_enabled_sig_mechanisms():
        print(f"Error: {sig_alg} is not enabled in this liboqs installation.")
        return

    # 2. Key Generation
    # Initialize the signature signer instance
    with oqs.Signature(sig_alg) as signer:
        print("[+] Generating key pair...")
        public_key = signer.generate_keypair()
        
        # In a real app, you would save these bytes to a file
        secret_key = signer.export_secret_key()
        
        print(f"    Public Key size:  {len(public_key)} bytes")
        print(f"    Secret Key size:  {len(secret_key)} bytes")
        
        # 3. Signing the Message
        message = b"This is a sensitive transaction message that needs authentication."
        print(f"\n[+] Signing message: '{message.decode()}'")
        
        # Generate the signature using the internal secret key
        signature = signer.sign(message)
        print(f"    Signature size:   {len(signature)} bytes")

    # 4. Verification (Simulating the Receiver)
    # The receiver doesn't have the signer instance anymore, 
    # they just instantiate the algorithm class to verify.
    with oqs.Signature(sig_alg) as verifier:
        print("\n[+] Verifying the signature...")
        
        is_valid = verifier.verify(message, signature, public_key)
        
        if is_valid:
            print("    ✅ Verification SUCCESS: The signature is authentic!")
        else:
            print("    ❌ Verification FAILED: The message or signature was tampered with.")
            
        # 5. Quick Tamper Test (Sanity Check)
        print("\n[+] Testing with a tampered message...")
        tampered_message = b"This is a malicious transaction message."
        
        is_valid_tampered = verifier.verify(tampered_message, signature, public_key)
        if not is_valid_tampered:
            print("    ✅ Verification correctly rejected the tampered message.")

if __name__ == "__main__":
    run_mldsa_demo()