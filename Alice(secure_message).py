from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding


# Derived Key from Task 3 
derived_key = "7e076ca1e09ea6ae611fc8e975e7f08d22a9472dc027f29c26a5138ce7a920e4"

# Random number from Task 4 
random_number = 5669385101169175838  

# Converting exported values to bytes
key = bytes.fromhex(derived_key[:64])[:32]   
iv = random_number.to_bytes(16, byteorder="big", signed=False)[:16]  


# Symmetric Encryption (AES-CBC)

def sym_encryption(key, iv, plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return cipher_text


# HMAC function

def derive_hmac(key, data):
    h1 = hmac.HMAC(key, hashes.SHA256())
    h1.update(data)
    return h1.finalize()


# Authenticated Encryption (Encrypt and then MAC)

def authenticated_encryption(message):
    cipher_text = sym_encryption(key, iv, message)
    mac = derive_hmac(key, cipher_text)
    return cipher_text, mac



message = "Wake up and finish work!"
cipher_text, mac = authenticated_encryption(message)

print(f"Key from Task 3): {derived_key}")
print(f"Random number from Task 4): {random_number}")
print(f"IV (from random number): {iv.hex()}")
print(f"Plaintext: {message}")
print(f"Ciphertext: {cipher_text.hex()}")
print(f"HMAC output: {mac.hex()}")

# Concatenated values to be sent from Alice to Bob
concatenated = (cipher_text, mac, iv)
