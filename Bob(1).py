import random
from digital_signature import Key, Sign, Verify

p = 1373
g = 2
print(f"\n[Bob] Public parameters: p = {p}, g = {g}\n")

bob_public, bob_private = Key()
print("[Bob] Public Key:", bob_public)
print("[Bob] Private Key:", bob_private, "\n")

b = random.randint(2, p - 2)
B = pow(g, b, p)

# Bob signs B
bob_signature = Sign(bob_private, str(B))
print(f"[Bob] B = {B}")
print(f"[Bob] B's signature = {bob_signature}\n")

#On Alice's terminal
print("Values to be entered on Alice's terminal:")
print(f"B = {B}")
print(f"Signature = {bob_signature}")
print(f"Bob's Public Key = {bob_public}\n")

#Testing of values
A = int(input(" Enter Alice's A value: "))
alice_signature = int(input("Enter Alice's signature: "))
alice_e = int(input("Enter Alice's e value: "))
alice_N = int(input("Enter Alice's N value: "))
alice_public = (alice_e, alice_N)

# Verification of Alice’s signature
if Verify(alice_public, str(A), alice_signature):
    print("Verification successful")
else:
    print("Verification failed")
# Derive shared secret value
shared_secret = pow(A, b, p)
print(f"[Bob] Shared secret = {shared_secret}")
