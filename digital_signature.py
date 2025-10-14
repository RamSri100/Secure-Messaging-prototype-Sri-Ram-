import hashlib
import random
from math import gcd

def modinv(a, m):
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Error in generating the inverse')
    return x % m


def Key():
    # Choose any two prime numbers
    p = random.choice([211, 223, 227, 229, 233, 239])
    q = random.choice([241, 251, 257, 263, 269, 271])
    
    # DeriveN
    N = p * q
    
    # Derive Euler’s value 
    phi = (p - 1) * (q - 1)
    
    # Select vaue of e, where gcd(e, φ(N)) = 1 and 2 < e < φ(N)
    e = random.randrange(3, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi)
    
    # Find d = e^-1 mod φ(N)
    d = modinv(e, phi)
    
    # Generate public and private keys
    return (e, N), (d, N)
public_key, private_key = Key()
print("Public Key (e, N):", public_key)
print("Private Key (d, N):", private_key)


# Hash Function 

def H(M):
    hash_value = int.from_bytes(hashlib.sha256(M.encode()).digest(), byteorder='big')
    return hash_value


# Signature Function

def Sign(private_key, M):
    d, N = private_key
    hash_val = H(M)
    signature = pow(hash_val, d, N)
    return signature

# Verification Function

def Verify(public_key, M, signature):
    e, N = public_key
    hash_val = H(M)
    verified_val = pow(signature, e, N)
    return 1 if verified_val == hash_val % N else 0


# Compute keys for Alice and Bob
alice_public, alice_private = Key()
bob_public, bob_private = Key()


print("Alice's Public Key:", alice_public)
print("Bob's Public Key:", bob_public)

# Alice signs the message
message = "Finish the work on time."
signature = Sign(alice_private, message)
print("\nAlice's Signature:", signature)


# Verification using Alice's public key

valid_result = Verify(alice_public, message, signature)
print("Result with Alice's public key:", valid_result)
if valid_result == 1:
    print("Valid result and public key is correct.")

"""
# Verification using Bob's public key

invalid_result = Verify(bob_public, message, signature)
print("Result with Bob's public key:", invalid_result)
if invalid_result == 0:
    print("Invalid result and public key is incorrect")
"""



