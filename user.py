import random
from signature import scalar_mult, G

class User:
    def __init__(self):
        # Generate a random private key (1 <= k < p)
        self.private_key = random.randint(1, 96)  # p = 97 in our curve
        # Derive the public key using scalar multiplication on generator point G
        self.public_key = scalar_mult(self.private_key, G)

    def sign(self, message):
        """
        Signs a message using the user's private key.
        Returns a tuple (r, s) as the signature.
        """
        from signature import sign_message
        return sign_message(message, self.private_key)

    def get_public_key(self):
        """
        Returns the user's public key (a point on the elliptic curve).
        """
        return self.public_key

    def get_private_key(self):
        """
        Returns the user's private key (for testing/demo purposes).
        ⚠️ In real systems, never expose private keys like this!
        """
        return self.private_key
