import random
from digital_signature import Key, Sign, Verify

p = 1373
g = 2
print(f"\n[Alice] Public values: p = {p}, g = {g}\n")

alice_public, alice_private = Key()
print("[Alice] Public Key:", alice_public)
print("[Alice] Private Key:", alice_private, "\n")

a = random.randint(2, p - 2)
A = pow(g, a, p)  

# Alice signs A
alice_signature = Sign(alice_private, str(A))
print(f"[Alice] A = {A}")
print(f"[Alice] A's signature = {alice_signature}\n")

#On Bob's terminal
print("Values to be entered on Bob's terminal:")
print(f"A = {A}")
print(f"Signature = {alice_signature}")
print(f"Alice's Public Key = {alice_public}\n")

#Testing of values
B = int(input("Enter Bob's B value: "))
bob_signature = int(input(" Enter Bob's signature : "))
bob_e = int(input("Enter Bob's e value: "))
bob_N = int(input("Enter Bob's N value: "))
bob_public = (bob_e, bob_N)

# Verification of Bob's signature
if Verify(bob_public, str(B), bob_signature):
    print("Verification successful")
else:
    print("Verification failed")
# Derive shared secret value
shared_secret = pow(B, a, p)
print(f"[Alice] Shared secret = {shared_secret}")
