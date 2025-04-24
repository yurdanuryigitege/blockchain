import hashlib as hs
import time
from dataclasses import dataclass, field
from signature import sign_message, verify_signature, G, p

@dataclass
class Block:
    index: int
    data: dict  # Changed to a dictionary to hold structured transaction
    previousHash: str
    sender_public_key: tuple  # Public key of the sender
    timestamp: float = field(default_factory=time.time)
    nonce: int = 0
    hash: str = field(init=False)
    signature: tuple = field(init=False)
    difficulty: int = 3
    private_key: int = field(default=None, repr=False)

    def __post_init__(self):
        # Calculate the block hash
        self.hash = self.calculate_hash()
        # Sign with sender's private key (assumed passed externally)
        if self.private_key:
            self.signature = sign_message(self.data, self.private_key)
        else:
            self.signature = None

    def mine_block(self, difficulty):
        target = "0" * difficulty
        while True:
            computed_hash = self.calculate_hash()
            if computed_hash.startswith(target):
                self.hash = computed_hash
                break
            self.nonce += 1

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.data}{self.previousHash}{self.nonce}"
        return hs.sha256(block_string.encode()).hexdigest()


class Blockchain:
    def __init__(self, difficulty=3):
        self.chain = []
        self.difficulty = difficulty
        # Create the genesis block (first block in the chain)
        genesis_block = Block(0, {"sender": "None", "recipient": "None", "amount": 0}, "0", sender_public_key=(0, 0))
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)

    def add_block(self, data, private_key, public_key):
        # Create a new block
        last_block = self.chain[-1]
        new_block = Block(len(self.chain), data, last_block.hash, sender_public_key=public_key)
        new_block.private_key = private_key  # Temporarily attach to sign
        new_block.__post_init__()  # Manually call post-init to generate signature
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def verify(self):
        # Verify the integrity of the blockchain
        for i in range(1, len(self.chain)):
            prev = self.chain[i - 1]
            curr = self.chain[i]

            # Check hash integrity and the chain linkage
            if curr.hash != curr.calculate_hash() or curr.previousHash != prev.hash:
                return False

            # Verify the signature of the current block's transaction
            if not verify_signature(curr.data, curr.signature, curr.sender_public_key):
                print(f"Invalid signature on block {curr.index}")
                return False

        return True
