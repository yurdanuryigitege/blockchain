# test_signature.py
from signature import sign_message, verify_signature, scalar_mult, G
import json

# Key generation
private_key = 17
public_key = scalar_mult(private_key, G)

# Transaction as structured data
transaction = {
    "sender": "Alice",
    "recipient": "Bob",
    "amount": 10
}

# Sign transaction
signature = sign_message(transaction, private_key)

# Verify signature
is_valid = verify_signature(transaction, signature, public_key)

print("Transaction:", transaction)
print("Signature:", signature)
print("Is the signature valid?", "✅ Yes" if is_valid else "❌ No")

# Tampering test
tampered_transaction = {
    "sender": "Alice",
    "recipient": "Eve",  # changed recipient
    "amount": 10
}

is_valid_after_tamper = verify_signature(tampered_transaction, signature, public_key)
print("\n--- Tampering Test ---")
print("Tampered transaction:", tampered_transaction)
print("Is the signature still valid?", "✅ Yes" if is_valid_after_tamper else "❌ No")
