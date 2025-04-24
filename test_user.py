from user import User
from signature import verify_signature

# Step 1: Create two users (Alice and Bob)
alice = User()
bob = User()

# Step 2: Let Alice create and sign a message
message = "Alice pays Bob 10 BTC"
signature = alice.sign(message)

# Step 3: Anyone can verify the signature using Alice's public key
is_valid = verify_signature(message, signature, alice.get_public_key())

print("Message:", message)
print("Signature:", signature)
print("Alice's Public Key:", alice.get_public_key())
print("Is the signature valid?", "✅ Yes" if is_valid else "❌ No")

# Optional: Tampering test
print("\n--- Tampering Test ---")
tampered_msg = "Alice pays Eve 100 BTC"
is_valid_after_tamper = verify_signature(tampered_msg, signature, alice.get_public_key())
print("Tampered message:", tampered_msg)
print("Is the signature still valid?", "✅ Yes" if is_valid_after_tamper else "❌ No")
