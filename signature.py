# signature.py
import random
import hashlib
import json

# Elliptic Curve: y^2 = x^3 + ax + b over F_p
a = 2
b = 3
p = 97
G = (3, 6)

# Modular inverse using Fermat's little theorem
def inverse_mod(k, p):
    return pow(k, -1, p)

# Elliptic curve point addition
def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        s = ((3 * x1**2 + a) * inverse_mod(2 * y1, p)) % p
    else:
        s = ((y2 - y1) * inverse_mod(x2 - x1, p)) % p
    x3 = (s**2 - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)

# Scalar multiplication using double-and-add
def scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

# Hash the message (as a string)
def hash_message(msg):
    if isinstance(msg, dict):  # Ensure dicts are converted to JSON consistently
        msg = json.dumps(msg, sort_keys=True)
    h = hashlib.sha256(msg.encode()).hexdigest()
    return int(h, 16)

# Create a digital signature (r, s)
def sign_message(msg, private_key):
    z = hash_message(msg)
    while True:
        k = random.randint(1, p - 1)
        R = scalar_mult(k, G)
        if R is None:
            continue
        r = R[0] % p
        if r == 0:
            continue
        s = (inverse_mod(k, p) * (z + r * private_key)) % p
        if s == 0:
            continue
        return (r, s)

# Verify the digital signature
def verify_signature(msg, signature, public_key):
    if isinstance(msg, dict):
        msg = json.dumps(msg, sort_keys=True)
    r, s = signature
    if not (1 <= r < p and 1 <= s < p):
        return False
    z = hash_message(msg)
    w = inverse_mod(s, p)
    u1 = (z * w) % p
    u2 = (r * w) % p
    P = point_add(scalar_mult(u1, G), scalar_mult(u2, public_key))
    if P is None:
        return False
    return P[0] % p == r
