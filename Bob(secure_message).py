from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding


# Derived Key from Task 3 
derived_key = "7e076ca1e09ea6ae611fc8e975e7f08d22a9472dc027f29c26a5138ce7a920e4"

# Random number from Task 4 
random_number = 5669385101169175838

# Converting exported values to bytes
key = bytes.fromhex(derived_key[:64])[:32]   
iv = random_number.to_bytes(16, byteorder="big", signed=False)[:16]


# Symmetric Decryption

def sym_decryption(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain_text = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plain_text.decode()


# Verification of HMAC

def derive_hmac(key, data):
    h1 = hmac.HMAC(key, hashes.SHA256())
    h1.update(data)
    return h1.finalize()


# Enter Alice's data

ciphertext_hex = input("Enter the ciphertext: ").strip()
mac_hex = input("Enter MAC (hex): ").strip()

cipher_text = bytes.fromhex(ciphertext_hex)
received_mac = bytes.fromhex(mac_hex)


# Decryption & Verification

derived_mac = derive_hmac(key, cipher_text)


print(f"Key from Task 3): {derived_key}")
print(f"Random number from Task 4): {random_number}")
print(f"IV (from random number): {iv.hex()}")
print(f"Received MAC:   {received_mac.hex()}")
print(f"Derived MAC:   {derived_mac.hex()}")

if derived_mac == received_mac:
    print("Verification successful. Integrity confirmed")
    plain_text = sym_decryption(key, iv, cipher_text)
    print(f"Decrypted message: {plain_text}")
else:
    print("Verification failed. Detected tampering.")
