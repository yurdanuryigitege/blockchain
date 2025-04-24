from blockchain import Blockchain
from signature import verify_signature  # Make sure to import this for signature verification

# Step 1: Create blockchain and add a valid block
bc = Blockchain()
transaction_data = {"sender": "Alice", "recipient": "Bob", "amount": 10}
private_key = 17
public_key = bc.chain[0].sender_public_key  # Use a public key for testing (from genesis block)

# Add the block
bc.add_block(transaction_data, private_key, public_key)

# Step 2: Print blockchain and verify
for block in bc.chain:
    print(f"Block #{block.index}: {block.data}")
    print(f"Signature: {block.signature}")

    # Check if signature exists before verifying it
    if block.signature:
        is_valid = verify_signature(block.data, block.signature, block.sender_public_key)
        print(f"Is the block valid? {'✅ Yes' if is_valid else '❌ No'}")
    else:
        print(f"Is the block valid? ❌ No signature found")

# Step 3: Tamper with a block's data and verify again
bc.chain[1].data = {"sender": "Alice", "recipient": "Eve", "amount": 100}  # Tamper data

# Verify blockchain after tampering
if bc.verify():
    print("\nBlockchain is valid ✅")
else:
    print("\nBlockchain is invalid ❌ (tampering detected!)")
