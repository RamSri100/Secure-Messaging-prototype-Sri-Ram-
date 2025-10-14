import hashlib

def simple_kdf(shared_secret, iterations):

    # Convert the value of shared secret into bytes
    k1 = str(shared_secret).encode()

    for i in range(iterations):

        # Implementing SHA-256
        k1 = hashlib.sha256(k1).digest()

    # Computed key is generated 
    return k1.hex()
if __name__ == "__main__":


    # Secret value generated in Diffie-Hellmen exchange
    shared_secret = int(input("Enter the value: "))

    # Number of iterations
    iterations = int(input("Enter the number of iterations to be performed  : "))

    # Computing derived key
    d_k = simple_kdf(shared_secret, iterations)

    print("Derived Key:")
    print(d_k)
