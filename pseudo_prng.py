import hashlib
import hmac
import os
import time
import secrets

class PRNG:
    def __init__(self):
        self.state = None

    def seeding(self, seed_value=None):
        if seed_value is None:
            seed_value = f"{time.time()}_{os.getpid()}_{secrets.token_hex(8)}"
        self.state = hashlib.sha256(seed_value.encode()).digest()
        return seed_value

    def reseeding(self, additional_entropy=None):
        if self.state is None:
            raise ValueError("Initialization failure. Call seed() first.")
        if additional_entropy is None:
            additional_entropy = secrets.token_bytes(16)
        self.state = hashlib.sha256(self.state + extra_entropy).digest()

    def generation(self, num_bytes=8, deterministic=False):
        if self.state is None:
            raise ValueError("Initialization failure. Call seed() first.")
        message = b"produce"
        if not deterministic:
            message += secrets.token_bytes(16)
        output = hmac.new(self.state, message, hashlib.sha256).digest()
        self.state = hmac.new(self.state, output, hashlib.sha256).digest()
        return int.from_bytes(output[:num_bytes], 'big')


# Generation of Randomness

if __name__ == "__main__":
    
    
    print("Random sequences:")
    prng_random = PRNG()
    prng_random.seeding()
    for i in range(2):
        print(f"Sequence {i+1}: {prng_random.generation()}")


    print("Deterministic:same seed generating same output")
    assigned_seed = "sample_seed_178"
    prng_x = PRNG()
    prng_y = PRNG()
    prng_x.seeding(assigned_seed)
    prng_y.seeding(assigned_seed)
    first_seq = [prng_x.generation(deterministic=True) for _ in range(2)]
    second_seq = [prng_y.generation(deterministic=True) for _ in range(2)]
    print("First Sequence:", first_seq)
    print("Second Sequence:", second_seq)
    

    print("Reseeding: different seeds generating different sequences")
    prng_p = PRNG()
    prng_q = PRNG()
    prng_p.seeding("seed_three")
    prng_q.seeding("seed_four")
    third_seq = [prng_p.generation(deterministic=True) for _ in range(2)]
    fourth_seq = [prng_q.generation(deterministic=True) for _ in range(2)]
    print("Third Sequence:", third_seq)
    print("Fourth Sequence:", fourth_seq)
   
